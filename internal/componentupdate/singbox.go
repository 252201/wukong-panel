package componentupdate

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// NewSingBox accepts only official stable Linux archives. The caller bounds
// supported target profiles and validates each candidate configuration.
func NewSingBox(dir, binary, arch string) *Controller {
	c := New(dir, binary, arch)
	c.name, c.repo, c.archive = "sing-box", "SagerNet/sing-box", true
	c.versionPattern = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	c.servicePattern = regexp.MustCompile(`^sing-box-wukong-[A-Za-z0-9_-]+$`)
	c.assetName = func(version, arch string) string { return "sing-box-" + version + "-linux-" + arch + ".tar.gz" }
	return c
}

func (c *Controller) unpack(archive, version string) (result string, err error) {
	input, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer input.Close()
	gz, err := gzip.NewReader(input)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	reader := tar.NewReader(io.LimitReader(gz, 256<<20))
	expected := "sing-box-" + version + "-linux-" + c.Architecture + "/sing-box"
	found := false
	for entries := 0; ; entries++ {
		if entries >= 64 {
			return "", errors.New("too many archive entries")
		}
		header, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
		if header.Name != expected {
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size >= maxBinary {
			return "", errors.New("invalid sing-box archive binary")
		}
		found = true
		out, e := os.CreateTemp(filepath.Dir(c.Binary), ".wukong-"+filepath.Base(c.Binary)+"-stage-*")
		if e != nil {
			return "", e
		}
		result = out.Name()
		stage := result
		defer func() {
			if err != nil {
				os.Remove(stage)
			}
		}()
		n, e := io.Copy(out, reader)
		if e == nil && n != header.Size {
			e = errors.New("incomplete sing-box binary")
		}
		if e == nil {
			e = out.Chmod(0755)
		}
		if e == nil {
			e = out.Sync()
		}
		closeErr := out.Close()
		if e != nil {
			return result, e
		}
		if closeErr != nil {
			return result, closeErr
		}
	}
	if !found {
		return "", errors.New("sing-box archive binary is missing")
	}
	return result, nil
}

// ConfigFile is a root-only snapshot stored in the recovery journal; it is
// never returned by the web or fleet API. File paths must stay in ConfigDir.
type ConfigFile struct {
	Path string `json:"path"`
	Old  []byte `json:"old"`
	New  []byte `json:"new"`
	Mode uint32 `json:"mode"`
}

func bytesSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (c *Controller) validateFiles(files []ConfigFile, recovery bool) error {
	total := 0
	seen := map[string]bool{}
	for _, f := range files {
		if !filepath.IsAbs(c.ConfigDir) || filepath.Dir(f.Path) != filepath.Clean(c.ConfigDir) || filepath.Ext(f.Path) != ".json" || seen[f.Path] || f.Mode&^0777 != 0 || f.Mode&0022 != 0 {
			return errors.New("invalid configuration recovery identity")
		}
		seen[f.Path] = true
		total += len(f.Old) + len(f.New)
		if len(f.Old) > 1<<20 || len(f.New) > 1<<20 || total > 32<<20 {
			return errors.New("configuration snapshot is too large")
		}
		current, e := fileSHA(f.Path)
		if e != nil {
			return e
		}
		if current != bytesSHA(f.Old) && (!recovery || current != bytesSHA(f.New)) {
			return errors.New("configuration changed outside the update transaction")
		}
	}
	return nil
}
func (c *Controller) writeFiles(files []ConfigFile, recovery bool) error {
	if e := c.validateFiles(files, recovery); e != nil {
		return e
	}
	for _, f := range files {
		data, mode := f.New, os.FileMode(0600)
		if recovery {
			data, mode = f.Old, os.FileMode(f.Mode)
		}
		tmp, e := os.CreateTemp(filepath.Dir(f.Path), ".wukong-config-*")
		if e != nil {
			return e
		}
		name := tmp.Name()
		if _, e = tmp.Write(data); e == nil {
			e = tmp.Chmod(mode)
		}
		if e == nil {
			e = tmp.Sync()
		}
		ce := tmp.Close()
		if e == nil {
			e = ce
		}
		if e == nil {
			e = os.Rename(name, f.Path)
		}
		os.Remove(name)
		if e != nil {
			return fmt.Errorf("cannot commit runtime configuration: %w", e)
		}
	}
	if len(files) > 0 {
		return syncDir(c.ConfigDir)
	}
	return nil
}
