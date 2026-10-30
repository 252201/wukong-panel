// Package componentupdate manages verified runtime updates and crash recovery.
// Service definitions are never changed by the updater.
package componentupdate

import (
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

const releaseURL = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
const maxBinary = 128 << 20

var calendarVersionPattern = regexp.MustCompile(`^\d{4}\.\d{1,2}\.\d{1,3}$`)

type progressContextKey struct{}

// ProgressReporter receives progress percent (0-100) and status message.
type ProgressReporter func(percent int, message string)

// WithProgress returns a new context configured with a progress reporter.
func WithProgress(ctx context.Context, fn ProgressReporter) context.Context {
	return context.WithValue(ctx, progressContextKey{}, fn)
}

func (c *Controller) reportProgress(ctx context.Context, percent int, message string) {
	if fn, ok := ctx.Value(progressContextKey{}).(ProgressReporter); ok && fn != nil {
		fn(percent, message)
	}
}

type progressReader struct {
	reader     io.Reader
	total      int64
	read       int64
	lastReport time.Time
	onProgress func(percent int, read, total int64)
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.read += int64(n)
		now := time.Now()
		if pr.onProgress != nil && (now.Sub(pr.lastReport) >= 250*time.Millisecond || (pr.total > 0 && pr.read == pr.total) || err != nil) {
			pr.lastReport = now
			pct := 0
			if pr.total > 0 {
				pct = int(float64(pr.read) / float64(pr.total) * 100)
				if pct > 100 {
					pct = 100
				}
			}
			pr.onProgress(pct, pr.read, pr.total)
		}
	}
	return n, err
}

// RunParallel executes fn concurrently for idx in 0..count-1 with a maximum concurrency limit.
// If count <= 0, it returns nil immediately.
// If any task returns an error or ctx is cancelled, execution halts and the first error is returned.
func RunParallel(ctx context.Context, limit int, count int, fn func(ctx context.Context, idx int) error) error {
	if count <= 0 {
		return nil
	}
	if limit <= 0 || limit > count {
		limit = count
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error

	setErr := func(err error) {
		if err != nil {
			once.Do(func() {
				firstErr = err
				cancel()
			})
		}
	}

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			setErr(ctx.Err())
			break
		}
		if firstErr != nil {
			break
		}
		wg.Add(1)
		idx := i
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			if ctx.Err() != nil {
				return
			}
			if err := fn(ctx, idx); err != nil {
				setErr(err)
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

type Service struct {
	Name    string `json:"name"`
	Manager string `json:"manager"`
}
type Controller struct {
	Dir, Binary, Architecture      string
	HTTP                           *http.Client
	Version                        func(context.Context, string) (string, error)
	Services                       func(context.Context) ([]Service, error)
	Restart                        func(context.Context, Service) error
	Stop                           func(context.Context, Service) error
	Prepare                        func(context.Context, string, string) ([]ConfigFile, error)
	Verify                         func(context.Context) error
	ConfigDir                      string
	AllowedTarget                  func(string) bool
	name, repo                     string
	versionPattern, servicePattern *regexp.Regexp
	assetName                      func(string, string) string
	archive                        bool
	unpackedSHA                    string
}
type asset struct {
	Version, URL, SHA256 string
	Size                 int64
}
type journal struct {
	OldSHA   string       `json:"oldSHA"`
	NewSHA   string       `json:"newSHA"`
	Services []Service    `json:"services"`
	Files    []ConfigFile `json:"files,omitempty"`
}

func New(dir, binary, arch string) *Controller {
	return &Controller{Dir: dir, Binary: binary, Architecture: arch,
		name: "cloudflared", repo: "cloudflare/cloudflared", versionPattern: calendarVersionPattern,
		servicePattern: regexp.MustCompile(`^cloudflared-wukong-[A-Za-z0-9_-]+$`),
		assetName:      func(_, arch string) string { return "cloudflared-linux-" + arch }, HTTP: &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 || r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Port() != "" {
				return errors.New("untrusted runtime download redirect")
			}
			switch r.URL.Hostname() {
			case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
				return nil
			}
			return errors.New("untrusted runtime download host")
		}}}
}

func (c *Controller) newer(a, b string) bool {
	if !c.versionPattern.MatchString(a) || !c.versionPattern.MatchString(b) {
		return false
	}
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for i := range x {
		av, _ := strconv.Atoi(x[i])
		bv, _ := strconv.Atoi(y[i])
		if av != bv {
			return av > bv
		}
	}
	return false
}

func (c *Controller) readState() (model.ComponentUpdateState, error) {
	var s model.ComponentUpdateState
	b, e := os.ReadFile(filepath.Join(c.Dir, "state.json"))
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return s, e
	}
	return s, nil
}

func (c *Controller) Status(ctx context.Context) (model.ComponentUpdateState, error) {
	s, e := c.readState()
	if e != nil {
		return s, e
	}
	s.Installed = false
	s.Writable = false
	s.UpdateAvailable = false
	s.CurrentVersion = ""
	s.Reason = ""
	info, e := os.Lstat(c.Binary)
	if errors.Is(e, os.ErrNotExist) {
		s.Reason = "runtime is not installed"
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		s.Reason = "connector must be a regular executable without group/world write access"
		return s, nil
	}
	s.CurrentVersion, e = c.Version(ctx, c.Binary)
	if e != nil {
		s.Reason = e.Error()
		return s, nil
	}
	s.Installed = true
	if !c.versionPattern.MatchString(s.CurrentVersion) {
		s.Reason = "cannot determine runtime version"
		return s, nil
	}
	if c.Architecture != "amd64" && c.Architecture != "arm64" {
		s.Reason = "unsupported architecture"
		return s, nil
	}
	if _, e = os.Lstat(filepath.Join(c.Dir, "pending.json")); e == nil {
		s.Reason = "update recovery is pending"
		return s, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return s, e
	}
	if _, e = c.Services(ctx); e != nil {
		s.Reason = e.Error()
		return s, nil
	}
	s.UpdateAvailable = c.newer(s.LatestVersion, s.CurrentVersion)
	if s.LatestVersion != "" && c.AllowedTarget != nil && !c.AllowedTarget(s.LatestVersion) {
		s.Reason = "latest release requires a newer panel compatibility profile"
		return s, nil
	}
	s.Writable = true
	return s, nil
}

func (c *Controller) request(ctx context.Context, url string) (*http.Response, error) {
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return nil, e
	}
	r.Header.Set("User-Agent", "wukong-panel/component-updater")
	r.Header.Set("Accept", "application/vnd.github+json")
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("runtime download HTTP %d", resp.StatusCode)
	}
	return resp, nil
}
func (c *Controller) latest(ctx context.Context) (asset, error) {
	resp, e := c.request(ctx, "https://api.github.com/repos/"+c.repo+"/releases/latest")
	if e != nil {
		return asset{}, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil {
		return asset{}, e
	}
	if len(b) > 1<<20 {
		return asset{}, errors.New("release metadata is too large")
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"assets"`
	}
	if e = json.Unmarshal(b, &release); e != nil {
		return asset{}, e
	}
	version := strings.TrimPrefix(release.Tag, "v")
	if release.Draft || release.Prerelease || !c.versionPattern.MatchString(version) {
		return asset{}, errors.New("invalid stable runtime release")
	}
	name := c.assetName(version, c.Architecture)
	var result asset
	count := 0
	for _, a := range release.Assets {
		if a.Name != name {
			continue
		}
		count++
		sha := strings.TrimPrefix(a.Digest, "sha256:")
		raw, err := hex.DecodeString(sha)
		url := "https://github.com/" + c.repo + "/releases/download/" + release.Tag + "/" + name
		if err != nil || len(raw) != sha256.Size || a.Digest != "sha256:"+sha || a.URL != url || a.Size <= 0 || a.Size >= maxBinary {
			return asset{}, errors.New("release asset lacks trusted SHA-256, size or URL")
		}
		result = asset{version, url, strings.ToLower(sha), a.Size}
	}
	if count != 1 {
		return asset{}, errors.New("release must contain exactly one matching Linux asset")
	}
	return result, nil
}

func (c *Controller) check(ctx context.Context) (model.ComponentUpdateState, error) {
	s, e := c.Status(ctx)
	if e != nil {
		return s, e
	}
	a, e := c.latest(ctx)
	s.CheckedAt = time.Now().UTC()
	s.LastError = ""
	if e != nil {
		s.LastError = e.Error()
		s.LatestVersion = ""
		s.UpdateAvailable = false
	} else {
		s.LatestVersion = a.Version
		s.UpdateAvailable = c.newer(a.Version, s.CurrentVersion)
	}
	if saveErr := c.save("state.json", s); saveErr != nil {
		return s, saveErr
	}
	if e == nil {
		return c.Status(ctx)
	}
	return s, e
}
func (c *Controller) configure(ctx context.Context, enabled bool) (model.ComponentUpdateState, error) {
	s, e := c.Status(ctx)
	if e != nil {
		return s, e
	}
	if enabled && !s.Writable {
		return s, errors.New(s.Reason)
	}
	if enabled && !s.AutoUpdate {
		s.AutoCheckedAt = time.Time{}
	}
	s.AutoUpdate = enabled
	if e = c.save("state.json", s); e != nil {
		return s, e
	}
	return s, nil
}

// Install resolves the stable release afresh. Existing connectors are never
// replaced as a side effect of deploying a node.
func (c *Controller) install(ctx context.Context) error {
	if c.archive {
		return errors.New("runtime installation is not supported by the update endpoint")
	}
	if _, e := os.Lstat(c.Binary); !errors.Is(e, os.ErrNotExist) {
		return errors.New("runtime already exists or cannot be inspected")
	}
	if c.Architecture != "amd64" && c.Architecture != "arm64" {
		return errors.New("unsupported runtime architecture")
	}
	a, e := c.latest(ctx)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(c.Binary), 0755); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(c.Binary), ".wukong-"+filepath.Base(c.Binary)+"-stage-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	resp, e := c.request(ctx, a.URL)
	if e != nil {
		f.Close()
		return e
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxBinary))
	resp.Body.Close()
	if e != nil {
		f.Close()
		return e
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		f.Close()
		return errors.New("runtime installation checksum or size mismatch")
	}
	if e = f.Chmod(0755); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	v, e := c.Version(ctx, f.Name())
	if e != nil {
		return e
	}
	if v != a.Version {
		return errors.New("installed asset version mismatch")
	}
	// Hard-link publication is atomic and fails if another installer has
	// created the destination in the meantime.
	if e = os.Link(f.Name(), c.Binary); e != nil {
		return e
	}
	return syncDir(filepath.Dir(c.Binary))
}

func (c *Controller) update(ctx context.Context, current, target string) (err error) {
	if !c.versionPattern.MatchString(current) || !c.versionPattern.MatchString(target) {
		return errors.New("invalid expected runtime versions")
	}
	if err = c.recover(ctx); err != nil {
		return err
	}
	s, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if !s.Writable {
		return errors.New(s.Reason)
	}
	if s.CurrentVersion == target {
		return nil
	} // An idempotent replay after successful replacement.
	if s.CurrentVersion != current {
		return errors.New("runtime changed; check versions again")
	}
	a, err := c.latest(ctx)
	if err != nil {
		return err
	}
	if c.AllowedTarget != nil && !c.AllowedTarget(target) {
		return errors.New("unsupported target compatibility profile")
	}
	if a.Version != target || !c.newer(target, current) {
		return errors.New("stable release changed or requested downgrade; check versions again")
	}
	c.reportProgress(ctx, 10, fmt.Sprintf("正在校验运行环境并准备更新 %s…", c.name))
	services, err := c.Services(ctx)
	if err != nil {
		return err
	}
	oldSHA, err := fileSHA(c.Binary)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.Binary), ".wukong-"+filepath.Base(c.Binary)+"-stage-*")
	if err != nil {
		return err
	}
	stage := tmp.Name()
	defer func() { os.Remove(stage) }()
	resp, err := c.request(ctx, a.URL)
	if err != nil {
		tmp.Close()
		return err
	}
	hash := sha256.New()
	pReader := &progressReader{
		reader: io.LimitReader(resp.Body, maxBinary),
		total:  a.Size,
		onProgress: func(pct int, read, total int64) {
			jobPct := 15 + int(float64(pct)*0.6)
			mbRead := float64(read) / (1024 * 1024)
			mbTotal := float64(total) / (1024 * 1024)
			var msg string
			if total > 0 {
				msg = fmt.Sprintf("正在下载 %s (%.1f MB / %.1f MB)…", c.name, mbRead, mbTotal)
			} else {
				msg = fmt.Sprintf("正在下载 %s (%.1f MB)…", c.name, mbRead)
			}
			c.reportProgress(ctx, jobPct, msg)
		},
	}
	n, copyErr := io.Copy(io.MultiWriter(tmp, hash), pReader)
	resp.Body.Close()
	if copyErr != nil {
		tmp.Close()
		return copyErr
	}
	if n != a.Size || hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		tmp.Close()
		return errors.New("runtime asset size or checksum mismatch")
	}
	if err = tmp.Chmod(0755); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	c.unpackedSHA = ""
	c.reportProgress(ctx, 80, fmt.Sprintf("正在校验下载文件并备份现行 %s…", c.name))
	if c.archive {
		c.reportProgress(ctx, 82, fmt.Sprintf("正在解压 %s 安装包…", c.name))
		archivePath := stage
		stage, err = c.unpack(archivePath, a.Version)
		os.Remove(archivePath)
		if err != nil {
			return err
		}
	}
	v, err := c.Version(ctx, stage)
	if err != nil {
		return err
	}
	if v != target {
		return errors.New("downloaded runtime version does not match release")
	}
	var files []ConfigFile
	if c.Prepare != nil {
		c.reportProgress(ctx, 85, fmt.Sprintf("正在校验与迁移现行配置…"))
		files, err = c.Prepare(ctx, stage, target)
		if err != nil {
			return err
		}
		if err = c.validateFiles(files, false); err != nil {
			return err
		}
	}
	if liveSHA, e := fileSHA(c.Binary); e != nil || liveSHA != oldSHA {
		return errors.New("connector binary changed during download")
	}
	freshServices, e := c.Services(ctx)
	if e != nil {
		return e
	}
	before, _ := json.Marshal(services)
	after, _ := json.Marshal(freshServices)
	if string(before) != string(after) {
		return errors.New("connector services changed during download")
	}
	backupSHA, err := copyAtomicWithSHA(c.Binary, c.Binary+".wukong-rollback", 0755)
	if err != nil {
		return err
	}
	if backupSHA != oldSHA {
		return errors.New("cannot verify runtime rollback binary")
	}
	var newSHA string
	if c.archive {
		if c.unpackedSHA != "" {
			newSHA = c.unpackedSHA
		} else {
			newSHA, e = fileSHA(stage)
			if e != nil {
				return e
			}
		}
	} else {
		newSHA = a.SHA256
	}
	j := journal{OldSHA: oldSHA, NewSHA: newSHA, Services: services, Files: files}
	if err = c.save("pending.json", j); err != nil {
		return err
	}
	// Every failure after the durable journal restores the old executable and
	// all connectors which were running at the beginning. A killed Agent
	// replays the same journal before starting its normal reconciliation.
	defer func() {
		if err != nil {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			err = errors.Join(err, c.restore(recoveryCtx, j))
		}
	}()
	if c.Stop != nil && len(services) > 0 {
		c.reportProgress(ctx, 88, fmt.Sprintf("正在安全暂停 %s 关联服务…", c.name))
		if err = RunParallel(ctx, 4, len(services), func(ctx context.Context, i int) error {
			return c.Stop(ctx, services[i])
		}); err != nil {
			return err
		}
	}
	if err = c.writeFiles(files, false); err != nil {
		return err
	}
	c.reportProgress(ctx, 92, fmt.Sprintf("正在替换可执行文件并平滑重启 %s 关联服务…", c.name))
	if err = os.Rename(stage, c.Binary); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(c.Binary)); err != nil {
		return err
	}
	if len(services) > 0 {
		if err = RunParallel(ctx, 4, len(services), func(ctx context.Context, i int) error {
			return c.Restart(ctx, services[i])
		}); err != nil {
			return err
		}
	}
	if c.Verify != nil {
		c.reportProgress(ctx, 96, fmt.Sprintf("正在并发验证 %s 节点代理与回环…", c.name))
		if err = c.Verify(ctx); err != nil {
			return err
		}
	}
	if v, err = c.Version(ctx, c.Binary); err != nil {
		return err
	}
	if v != target {
		return errors.New("installed runtime version verification failed")
	}
	s.LatestVersion = target
	s.CurrentVersion = target
	s.UpdateAvailable = false
	s.CheckedAt = time.Now().UTC()
	s.UpdatedAt = s.CheckedAt
	s.LastError = ""
	if err = c.save("state.json", s); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(c.Dir, "pending.json")); err != nil {
		return err
	}
	return syncDir(c.Dir)
}

func (c *Controller) recover(ctx context.Context) error {
	b, e := os.ReadFile(filepath.Join(c.Dir, "pending.json"))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var j journal
	if e = json.Unmarshal(b, &j); e != nil {
		return e
	}
	return c.restore(ctx, j)
}

func (c *Controller) restore(ctx context.Context, j journal) error {
	for _, s := range j.Services {
		if !c.servicePattern.MatchString(s.Name) || (s.Manager != "systemd" && s.Manager != "openrc") {
			return errors.New("invalid recovery service")
		}
	}
	old, e := fileSHA(c.Binary + ".wukong-rollback")
	if e != nil || old != j.OldSHA || len(old) != 64 {
		return errors.New("runtime rollback checksum mismatch")
	}
	live, e := fileSHA(c.Binary)
	if e != nil {
		return e
	}
	if live != j.OldSHA && live != j.NewSHA {
		return errors.New("external connector change prevents automatic rollback")
	}
	if e = c.validateFiles(j.Files, true); e != nil {
		return e
	}
	if c.Stop != nil && len(j.Services) > 0 {
		if e = RunParallel(ctx, 4, len(j.Services), func(ctx context.Context, i int) error {
			return c.Stop(ctx, j.Services[i])
		}); e != nil {
			return e
		}
	}
	if e = copyAtomic(c.Binary+".wukong-rollback", c.Binary, 0755); e != nil {
		return e
	}
	if e = c.writeFiles(j.Files, true); e != nil {
		return e
	}
	if len(j.Services) > 0 {
		if e = RunParallel(ctx, 4, len(j.Services), func(ctx context.Context, i int) error {
			return c.Restart(ctx, j.Services[i])
		}); e != nil {
			return e
		}
	}
	if e = os.Remove(filepath.Join(c.Dir, "pending.json")); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return syncDir(c.Dir)
}

func (c *Controller) auto(ctx context.Context) error {
	if e := c.recover(ctx); e != nil {
		return e
	}
	s, e := c.Status(ctx)
	if e != nil || !s.AutoUpdate || !s.Writable {
		return e
	}
	if !s.AutoCheckedAt.IsZero() && time.Since(s.AutoCheckedAt) < 24*time.Hour {
		return nil
	}
	s.AutoCheckedAt = time.Now().UTC()
	if e = c.save("state.json", s); e != nil {
		return e
	}
	s, e = c.check(ctx)
	if e == nil && s.UpdateAvailable {
		e = c.update(ctx, s.CurrentVersion, s.LatestVersion)
	}
	if e != nil {
		saved, _ := c.readState()
		saved.LastError = e.Error()
		if se := c.save("state.json", saved); se != nil {
			return errors.Join(e, se)
		}
	}
	return e
}

func fileSHA(path string) (string, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("connector is not a regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func copyAtomicWithSHA(source, target string, mode os.FileMode) (string, error) {
	input, e := os.Open(source)
	if e != nil {
		return "", e
	}
	defer input.Close()
	f, e := os.CreateTemp(filepath.Dir(target), ".wukong-"+filepath.Base(target)+"-copy-*")
	if e != nil {
		return "", e
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	if _, e = io.Copy(io.MultiWriter(f, h), input); e == nil {
		e = f.Chmod(mode)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return "", e
	}
	if ce != nil {
		return "", ce
	}
	if e = os.Rename(f.Name(), target); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), syncDir(filepath.Dir(target))
}

func copyAtomic(source, target string, mode os.FileMode) error {
	_, err := copyAtomicWithSHA(source, target, mode)
	return err
}
func syncDir(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (c *Controller) save(name string, v any) error {
	if e := os.MkdirAll(c.Dir, 0700); e != nil {
		return e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(c.Dir, ".update-state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(f.Name(), filepath.Join(c.Dir, name)); e != nil {
		return e
	}
	return syncDir(c.Dir)
}
