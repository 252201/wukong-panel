package componentupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

// Lock across Agent processes, CLI deployments and Agent restarts. The lock
// lives next to the binary so different data directories cannot race on it.
func (c *Controller) withLock(ctx context.Context, fn func() error) error {
	if !filepath.IsAbs(c.Binary) {
		return errors.New("cloudflared binary path must be absolute")
	}
	if e := os.MkdirAll(filepath.Dir(c.Binary), 0755); e != nil {
		return e
	}
	f, e := os.OpenFile(c.Binary+".wukong-update.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if !errors.Is(e, syscall.EWOULDBLOCK) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if e = ctx.Err(); e != nil {
		return e
	}
	// An interrupted download never leaves a permanent cache of large binaries.
	for _, pattern := range []string{".wukong-" + filepath.Base(c.Binary) + "-stage-*", ".wukong-" + filepath.Base(c.Binary) + "-copy-*", ".wukong-" + filepath.Base(c.Binary) + ".wukong-rollback-copy-*"} {
		files, _ := filepath.Glob(filepath.Join(filepath.Dir(c.Binary), pattern))
		for _, p := range files {
			if info, e := os.Lstat(p); e == nil && info.Mode().IsRegular() {
				if e = os.Remove(p); e != nil {
					return e
				}
			}
		}
	}
	return fn()
}
func (c *Controller) Install(ctx context.Context) error {
	return c.withLock(ctx, func() error { return c.install(ctx) })
}
func (c *Controller) Update(ctx context.Context, from, to string) error {
	return c.withLock(ctx, func() error { return c.update(ctx, from, to) })
}
func (c *Controller) Recover(ctx context.Context) error {
	// A normal Agent without cloudflared must not create files in /usr/local/bin.
	if _, e := os.Lstat(filepath.Join(c.Dir, "pending.json")); errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return c.withLock(ctx, func() error { return c.recover(ctx) })
}
func (c *Controller) Auto(ctx context.Context) error {
	s, e := c.readState()
	if e != nil {
		return e
	}
	if !s.AutoUpdate {
		return c.Recover(ctx)
	}
	return c.withLock(ctx, func() error { return c.auto(ctx) })
}
func (c *Controller) Check(ctx context.Context) (s model.ComponentUpdateState, e error) {
	e = c.withLock(ctx, func() error { s, e = c.check(ctx); return e })
	return
}
func (c *Controller) Configure(ctx context.Context, enabled bool) (s model.ComponentUpdateState, e error) {
	e = c.withLock(ctx, func() error { s, e = c.configure(ctx, enabled); return e })
	return
}
