package cloudflaredupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fixture(t *testing.T) (*Controller, *string, *int) {
	t.Helper()
	root := t.TempDir()
	c := New(filepath.Join(root, "state"), filepath.Join(root, "cloudflared"), "amd64")
	if e := os.WriteFile(c.Binary, []byte("2026.8.2"), 0755); e != nil {
		t.Fatal(e)
	}
	c.Version = func(ctx context.Context, path string) (string, error) {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		b, e := os.ReadFile(path)
		return string(b), e
	}
	c.Services = func(context.Context) ([]Service, error) {
		return []Service{{"cloudflared-wukong-test", "systemd"}}, nil
	}
	c.Restart = func(context.Context, Service) error { return nil }
	version := "2026.9.3"
	calls := 0
	c.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var body []byte
		if r.URL.String() == releaseURL {
			body = metadata(version, c.Architecture)
		} else if r.URL.String() == "https://github.com/cloudflare/cloudflared/releases/download/"+version+"/cloudflared-linux-"+c.Architecture {
			body = []byte(version)
		} else {
			return nil, errors.New("unexpected download URL")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
	})
	return c, &version, &calls
}
func metadata(version, arch string) []byte {
	h := sha256.Sum256([]byte(version))
	b, _ := json.Marshal(map[string]any{"tag_name": version, "assets": []map[string]any{{"name": "cloudflared-linux-" + arch, "browser_download_url": "https://github.com/cloudflare/cloudflared/releases/download/" + version + "/cloudflared-linux-" + arch, "digest": "sha256:" + hex.EncodeToString(h[:]), "size": len(version)}}})
	return b
}
func expectBinary(t *testing.T, c *Controller, want string) {
	t.Helper()
	b, e := os.ReadFile(c.Binary)
	if e != nil || string(b) != want {
		t.Fatalf("binary %q: %v; want %s", b, e, want)
	}
}

func TestInstallResolvesNewestStableAndArchitectures(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			c, v, _ := fixture(t)
			c.Architecture = arch
			os.Remove(c.Binary)
			*v = "2026.10.1"
			if e := c.Install(context.Background()); e != nil {
				t.Fatal(e)
			}
			expectBinary(t, c, *v)
			*v = "2026.10.2"
			if e := c.Install(context.Background()); e == nil {
				t.Fatal("existing connector overwritten")
			}
			expectBinary(t, c, "2026.10.1")
		})
	}
}
func TestChecksumFailureNeverReplacesOrRestarts(t *testing.T) {
	c, _, _ := fixture(t)
	old := c.HTTP.Transport
	restarts := 0
	c.Restart = func(context.Context, Service) error { restarts++; return nil }
	c.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		resp, e := old.RoundTrip(r)
		if e == nil && r.URL.String() != releaseURL {
			resp.Body = io.NopCloser(strings.NewReader("malware!"))
		}
		return resp, e
	})
	if e := c.Update(context.Background(), "2026.8.2", "2026.9.3"); e == nil {
		t.Fatal("invalid asset accepted")
	}
	expectBinary(t, c, "2026.8.2")
	if restarts != 0 {
		t.Fatal("service restarted before validation")
	}
}
func TestUpdateAndReplayPreservePolicy(t *testing.T) {
	c, _, _ := fixture(t)
	if _, e := c.Configure(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	if e := c.Update(context.Background(), "2026.8.2", "2026.9.3"); e != nil {
		t.Fatal(e)
	}
	expectBinary(t, c, "2026.9.3")
	if e := c.Update(context.Background(), "2026.8.2", "2026.9.3"); e != nil {
		t.Fatal("replay:", e)
	}
	s, e := c.Status(context.Background())
	if e != nil || !s.AutoUpdate || s.UpdateAvailable || s.UpdatedAt.IsZero() {
		t.Fatalf("state %#v %v", s, e)
	}
	b, _ := os.ReadFile(c.Binary + ".wukong-rollback")
	if string(b) != "2026.8.2" {
		t.Fatal("incorrect rollback executable")
	}
}
func TestRestartFailureAndCancellationRollback(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "restart", true: "cancellation"}[cancelled], func(t *testing.T) {
			c, _, _ := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			seen := []string{}
			c.Restart = func(ctx context.Context, s Service) error {
				b, _ := os.ReadFile(c.Binary)
				seen = append(seen, string(b))
				if string(b) == "2026.9.3" {
					if cancelled {
						cancel()
						return ctx.Err()
					}
					return errors.New("new connector failed")
				}
				return ctx.Err()
			}
			if e := c.Update(ctx, "2026.8.2", "2026.9.3"); e == nil {
				t.Fatal("failure reported success")
			}
			expectBinary(t, c, "2026.8.2")
			if strings.Join(seen, ",") != "2026.9.3,2026.8.2" {
				t.Fatal(seen)
			}
			if _, e := os.Stat(filepath.Join(c.Dir, "pending.json")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("rollback journal not removed", e)
			}
		})
	}
}
func interrupted(t *testing.T, c *Controller) {
	t.Helper()
	old, _ := fileSHA(c.Binary)
	if e := copyAtomic(c.Binary, c.Binary+".wukong-rollback", 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(c.Binary, []byte("2026.9.3"), 0755); e != nil {
		t.Fatal(e)
	}
	newSHA, _ := fileSHA(c.Binary)
	if e := c.save("pending.json", journal{old, newSHA, []Service{{"cloudflared-wukong-test", "openrc"}}}); e != nil {
		t.Fatal(e)
	}
}
func TestRestartRecoveryRetriesAndDetectsCorruption(t *testing.T) {
	c, _, _ := fixture(t)
	interrupted(t, c)
	c.Restart = func(context.Context, Service) error { return errors.New("not ready") }
	if e := c.Recover(context.Background()); e == nil {
		t.Fatal("failed service recovery accepted")
	}
	expectBinary(t, c, "2026.8.2")
	if _, e := os.Stat(filepath.Join(c.Dir, "pending.json")); e != nil {
		t.Fatal("pending recovery lost")
	}
	c.Restart = func(context.Context, Service) error { return nil }
	if e := c.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	interrupted(t, c)
	os.WriteFile(c.Binary+".wukong-rollback", []byte("corrupt"), 0755)
	if e := c.Recover(context.Background()); e == nil {
		t.Fatal("corrupt backup restored")
	}
	expectBinary(t, c, "2026.9.3")
}
func TestExternalChangesAndVersionMismatchAreRejected(t *testing.T) {
	for _, kind := range []string{"stale", "downgrade", "release changed", "external binary", "service set", "asset version"} {
		t.Run(kind, func(t *testing.T) {
			c, v, _ := fixture(t)
			current, target := "2026.8.2", "2026.9.3"
			switch kind {
			case "stale":
				current = "2026.8.1"
			case "downgrade":
				target = "2026.7.1"
			case "release changed":
				*v = "2026.10.1"
			case "external binary":
				old := c.HTTP.Transport
				c.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.String() != releaseURL {
						os.WriteFile(c.Binary, []byte("external"), 0755)
					}
					return old.RoundTrip(r)
				})
			case "service set":
				calls := 0
				c.Services = func(context.Context) ([]Service, error) {
					calls++
					if calls >= 3 {
						return nil, nil
					}
					return []Service{{"cloudflared-wukong-test", "systemd"}}, nil
				}
			case "asset version":
				original := c.Version
				c.Version = func(ctx context.Context, p string) (string, error) {
					if p != c.Binary {
						return "2026.9.2", nil
					}
					return original(ctx, p)
				}
			}
			if e := c.Update(context.Background(), current, target); e == nil {
				t.Fatal("unsafe update accepted")
			}
			want := "2026.8.2"
			if kind == "external binary" {
				want = "external"
			}
			expectBinary(t, c, want)
		})
	}
}
func TestReleaseMetadataFailsClosed(t *testing.T) {
	for _, kind := range []string{"digest", "url", "duplicate", "prerelease", "tag", "missing", "size"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _ := fixture(t)
			var meta map[string]any
			json.Unmarshal(metadata("2026.9.3", "amd64"), &meta)
			assets := meta["assets"].([]any)
			a := assets[0].(map[string]any)
			switch kind {
			case "digest":
				delete(a, "digest")
			case "url":
				a["browser_download_url"] = "https://evil.test/binary"
			case "duplicate":
				meta["assets"] = append(assets, a)
			case "prerelease":
				meta["prerelease"] = true
			case "tag":
				meta["tag_name"] = "../../bin/sh"
			case "missing":
				meta["assets"] = []any{}
			case "size":
				a["size"] = maxBinary
			}
			b, _ := json.Marshal(meta)
			c.HTTP.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
			})
			if _, e := c.Check(context.Background()); e == nil {
				t.Fatal("untrusted release accepted")
			}
			s, _ := c.Status(context.Background())
			if s.UpdateAvailable || s.LastError == "" {
				t.Fatal("failure hidden in status", s)
			}
		})
	}
}
func TestAutoPolicyDailyAndManualCheckIndependence(t *testing.T) {
	c, _, calls := fixture(t)
	if e := c.Auto(context.Background()); e != nil {
		t.Fatal(e)
	}
	if *calls != 0 {
		t.Fatal("disabled auto update queried releases")
	}
	if _, e := c.Check(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Configure(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	if e := c.Auto(context.Background()); e != nil {
		t.Fatal(e)
	}
	expectBinary(t, c, "2026.9.3")
	n := *calls
	if e := c.Auto(context.Background()); e != nil {
		t.Fatal(e)
	}
	if *calls != n {
		t.Fatal("auto check exceeded daily frequency")
	}
	s, _ := c.readState()
	s.AutoCheckedAt = time.Now().Add(-25 * time.Hour)
	c.save("state.json", s)
	if e := c.Auto(context.Background()); e != nil {
		t.Fatal(e)
	}
	if *calls != n+1 {
		t.Fatal("daily recheck missing")
	}
}
func TestSymlinkAndUnmanagedServiceRestrictions(t *testing.T) {
	c, _, _ := fixture(t)
	os.Rename(c.Binary, c.Binary+".real")
	os.Symlink(c.Binary+".real", c.Binary)
	s, e := c.Status(context.Background())
	if e != nil || s.Writable {
		t.Fatal("symlink accepted", s, e)
	}
	os.Remove(c.Binary)
	os.Rename(c.Binary+".real", c.Binary)
	c.Services = func(context.Context) ([]Service, error) { return nil, errors.New("unmanaged connector") }
	s, e = c.Status(context.Background())
	if e != nil || s.Writable {
		t.Fatal("unmanaged connector accepted", s, e)
	}
	if _, e = c.Configure(context.Background(), true); e == nil {
		t.Fatal("auto enabled for unmanaged connector")
	}
}
func TestRedirectPolicy(t *testing.T) {
	c, _, _ := fixture(t)
	for _, value := range []string{"http://github.com/binary", "https://evil.test/binary", "https://github.com:443/binary"} {
		u, _ := url.Parse(value)
		if e := c.HTTP.CheckRedirect(&http.Request{URL: u}, nil); e == nil {
			t.Fatal("unsafe redirect accepted", value)
		}
	}
	u, _ := url.Parse("https://release-assets.githubusercontent.com/binary")
	if e := c.HTTP.CheckRedirect(&http.Request{URL: u}, nil); e != nil {
		t.Fatal(e)
	}
}

func TestBinaryLockSerializesDifferentStateDirectories(t *testing.T) {
	c, _, _ := fixture(t)
	other := *c
	other.Dir = filepath.Join(t.TempDir(), "other-state")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- c.withLock(context.Background(), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	called := false
	e := other.withLock(ctx, func() error { called = true; return nil })
	close(release)
	if first := <-done; first != nil {
		t.Fatal(first)
	}
	if !errors.Is(e, context.DeadlineExceeded) || called {
		t.Fatalf("lock bypassed: %v, called=%v", e, called)
	}
	if e = other.withLock(context.Background(), func() error { called = true; return nil }); e != nil || !called {
		t.Fatalf("lock not released: %v", e)
	}
}

func TestStateCommitFailureRollsBackBinaryAndServices(t *testing.T) {
	c, _, _ := fixture(t)
	restarts := 0
	c.Restart = func(context.Context, Service) error {
		restarts++
		if restarts == 1 {
			return os.Mkdir(filepath.Join(c.Dir, "state.json"), 0700)
		}
		return nil
	}
	if e := c.Update(context.Background(), "2026.8.2", "2026.9.3"); e == nil {
		t.Fatal("state write failure was ignored")
	}
	expectBinary(t, c, "2026.8.2")
	if restarts != 2 {
		t.Fatalf("rollback did not restart original service: %d", restarts)
	}
	if _, e := os.Stat(filepath.Join(c.Dir, "pending.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("recovery journal not cleared: %v", e)
	}
}
