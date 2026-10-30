package componentupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func runtimeArchive(t *testing.T, version, arch string, duplicate bool, kind byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	count := 1
	if duplicate {
		count = 2
	}
	for i := 0; i < count; i++ {
		h := &tar.Header{Name: "sing-box-" + version + "-linux-" + arch + "/sing-box", Typeflag: kind, Mode: 0755, Size: int64(len(version))}
		if kind == tar.TypeSymlink {
			h.Linkname = "/etc/passwd"
			h.Size = 0
		}
		if e := tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if kind == tar.TypeReg {
			if _, e := tw.Write([]byte(version)); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func singBoxFixture(t *testing.T, arch string) (*Controller, *[]byte, string) {
	t.Helper()
	c, _, _ := fixture(t)
	other := NewSingBox(c.Dir, c.Binary, arch)
	other.Version = c.Version
	other.Services = func(context.Context) ([]Service, error) {
		return []Service{{Name: "sing-box-wukong-test", Manager: "systemd"}}, nil
	}
	other.Restart = c.Restart
	other.ConfigDir = filepath.Join(t.TempDir(), "configs")
	os.MkdirAll(other.ConfigDir, 0700)
	path := filepath.Join(other.ConfigDir, "node.json")
	os.WriteFile(path, []byte(`{"version":"old"}`), 0640)
	other.Prepare = func(context.Context, string, string) ([]ConfigFile, error) {
		return []ConfigFile{{Path: path, Old: []byte(`{"version":"old"}`), New: []byte(`{"version":"new"}`), Mode: 0640}}, nil
	}
	other.Stop = func(context.Context, Service) error { return nil }
	other.Verify = func(context.Context) error { return nil }
	payload := runtimeArchive(t, "1.14.2", arch, false, tar.TypeReg)
	os.WriteFile(other.Binary, []byte("1.14.1"), 0755)
	other.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		body := payload
		if r.URL.String() == "https://api.github.com/repos/SagerNet/sing-box/releases/latest" {
			sum := sha256.Sum256(payload)
			name := other.assetName("1.14.2", arch)
			body, _ = json.Marshal(map[string]any{"tag_name": "v1.14.2", "assets": []map[string]any{{"name": name, "browser_download_url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/" + name, "digest": "sha256:" + hex.EncodeToString(sum[:]), "size": len(payload)}}})
		} else if !strings.HasPrefix(r.URL.String(), "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/") {
			return nil, errors.New("untrusted request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})
	return other, &payload, path
}
func TestSingBoxUpdatesBothArchitecturesAndConfigs(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			c, _, path := singBoxFixture(t, arch)
			order := []string{}
			c.Stop = func(context.Context, Service) error { order = append(order, "stop"); return nil }
			c.Restart = func(context.Context, Service) error {
				expectBinary(t, c, "1.14.2")
				data, _ := os.ReadFile(path)
				if !bytes.Contains(data, []byte("new")) {
					t.Fatal("config not migrated")
				}
				order = append(order, "restart")
				return nil
			}
			c.Verify = func(context.Context) error { order = append(order, "probe"); return nil }
			if _, e := c.Check(t.Context()); e != nil {
				t.Fatal(e)
			}
			if e := c.Update(t.Context(), "1.14.1", "1.14.2"); e != nil {
				t.Fatal(e)
			}
			if strings.Join(order, ",") != "stop,restart,probe" {
				t.Fatal(order)
			}
			if e := c.Update(t.Context(), "1.14.1", "1.14.2"); e != nil {
				t.Fatal(e)
			}
			expectBinary(t, c, "1.14.2")
			if data, _ := os.ReadFile(c.Binary + ".wukong-rollback"); string(data) != "1.14.1" {
				t.Fatal("rollback binary missing")
			}
		})
	}
}
func TestSingBoxRejectedArchiveAndPreparationDoNotMutate(t *testing.T) {
	for _, kind := range []string{"duplicate", "symlink", "wrong-arch", "incompatible", "config-change", "unsupported-profile"} {
		t.Run(kind, func(t *testing.T) {
			c, payload, path := singBoxFixture(t, "amd64")
			switch kind {
			case "duplicate":
				*payload = runtimeArchive(t, "1.14.2", "amd64", true, tar.TypeReg)
			case "symlink":
				*payload = runtimeArchive(t, "1.14.2", "amd64", false, tar.TypeSymlink)
			case "wrong-arch":
				*payload = runtimeArchive(t, "1.14.2", "arm64", false, tar.TypeReg)
			case "incompatible":
				c.Prepare = func(context.Context, string, string) ([]ConfigFile, error) {
					return nil, errors.New("candidate rejects configuration")
				}
			case "config-change":
				original := c.Prepare
				c.Prepare = func(ctx context.Context, b, v string) ([]ConfigFile, error) {
					files, e := original(ctx, b, v)
					os.WriteFile(path, []byte(`{"external":true}`), 0600)
					return files, e
				}
			case "unsupported-profile":
				c.AllowedTarget = func(string) bool { return false }
			}
			calls := 0
			c.Stop = func(context.Context, Service) error { calls++; return nil }
			c.Restart = c.Stop
			if e := c.Update(t.Context(), "1.14.1", "1.14.2"); e == nil {
				t.Fatal("invalid update accepted")
			}
			expectBinary(t, c, "1.14.1")
			if calls != 0 {
				t.Fatal("service touched", calls)
			}
			staged, _ := filepath.Glob(filepath.Join(filepath.Dir(c.Binary), ".wukong-*-stage-*"))
			if len(staged) > 0 {
				t.Fatal("archive staging leaked", staged)
			}
		})
	}
}
func TestSingBoxProbeFailureAndInterruptedRecoveryRestoreConfigs(t *testing.T) {
	c, _, path := singBoxFixture(t, "amd64")
	c.Verify = func(context.Context) error { return errors.New("protocol probe failed") }
	c.Restart = func(ctx context.Context, s Service) error {
		version, _ := c.Version(ctx, c.Binary)
		if version == "1.14.1" {
			return errors.New("old service temporarily unavailable")
		}
		return nil
	}
	if e := c.Update(t.Context(), "1.14.1", "1.14.2"); e == nil {
		t.Fatal("probe failure ignored")
	}
	expectBinary(t, c, "1.14.1")
	data, _ := os.ReadFile(path)
	if string(data) != `{"version":"old"}` {
		t.Fatal("config not restored")
	}
	info, e := os.Stat(filepath.Join(c.Dir, "pending.json"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("durable private journal missing", e)
	}
	c.Restart = func(context.Context, Service) error { return nil }
	if e = c.Recover(t.Context()); e != nil {
		t.Fatal(e)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0640 {
		t.Fatal("original mode not restored")
	}
	if _, e = os.Stat(filepath.Join(c.Dir, "pending.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("journal not removed", e)
	}
}
func TestConfigRecoveryRejectsExternalChangesAndPathEscape(t *testing.T) {
	c, _, path := singBoxFixture(t, "amd64")
	files, _ := c.Prepare(t.Context(), "", "1.14.2")
	files[0].Path = filepath.Join(filepath.Dir(c.ConfigDir), "outside.json")
	if e := c.writeFiles(files, false); e == nil {
		t.Fatal("path escape accepted")
	}
	files[0].Path = path
	os.WriteFile(path, []byte(`{"external":true}`), 0600)
	if e := c.writeFiles(files, true); e == nil {
		t.Fatal("external change overwritten")
	}
}

func TestSingBoxMultiServiceParallelRestart(t *testing.T) {
	c, _, _ := singBoxFixture(t, "amd64")
	services := make([]Service, 6)
	for i := range services {
		services[i] = Service{Name: fmt.Sprintf("sing-box-wukong-svc-%d", i), Manager: "systemd"}
	}
	c.Services = func(context.Context) ([]Service, error) {
		return services, nil
	}

	var activeRestarts int64
	var maxActiveRestarts int64
	var stoppedServices int64
	c.Stop = func(ctx context.Context, s Service) error {
		atomic.AddInt64(&stoppedServices, 1)
		return nil
	}
	c.Restart = func(ctx context.Context, s Service) error {
		cur := atomic.AddInt64(&activeRestarts, 1)
		for {
			old := atomic.LoadInt64(&maxActiveRestarts)
			if cur <= old || atomic.CompareAndSwapInt64(&maxActiveRestarts, old, cur) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt64(&activeRestarts, -1)
		return nil
	}

	if err := c.Update(t.Context(), "1.14.1", "1.14.2"); err != nil {
		t.Fatal(err)
	}
	if stoppedServices != int64(len(services)) {
		t.Fatalf("expected %d stopped services, got %d", len(services), stoppedServices)
	}
	if maxActiveRestarts < 2 {
		t.Fatalf("expected parallel restarts (at least concurrency 2), got %d", maxActiveRestarts)
	}
	if c.unpackedSHA == "" {
		t.Fatal("expected unpackedSHA to be recorded during unpack")
	}
}

func TestSingBoxReportsGranularProgress(t *testing.T) {
	c, _, _ := singBoxFixture(t, "amd64")
	var pcts []int
	var msgs []string
	ctx := WithProgress(context.Background(), func(pct int, msg string) {
		pcts = append(pcts, pct)
		msgs = append(msgs, msg)
	})
	if err := c.Update(ctx, "1.14.1", "1.14.2"); err != nil {
		t.Fatal(err)
	}
	hasUnpack := false
	hasMigrate := false
	hasRestart := false
	for _, p := range pcts {
		if p == 82 {
			hasUnpack = true
		}
		if p == 85 {
			hasMigrate = true
		}
		if p == 92 {
			hasRestart = true
		}
	}
	if !hasUnpack || !hasMigrate || !hasRestart {
		t.Fatalf("missing expected sing-box progress milestones: %v, msgs: %v", pcts, msgs)
	}
}
