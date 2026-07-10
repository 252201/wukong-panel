package store

import (
	"path/filepath"
	"testing"

	"github.com/252201/wukong-panel/internal/security"
)

func TestAuthenticationLifecycle(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	password, created, err := s.EnsureAdmin()
	if err != nil || !created {
		t.Fatalf("admin init failed: %v", err)
	}
	id, mustChange, err := s.Authenticate("admin", password)
	if err != nil || id == 0 || !mustChange {
		t.Fatalf("authentication failed: %v", err)
	}
	session, err := s.CreateSession(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(session.Token); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(id, "new-test-password-2026"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(session.Token); err == nil {
		t.Fatal("password change did not revoke session")
	}
}

func TestDemoSeedIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	vault, err := security.OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SeedDemo(vault); err != nil {
		t.Fatal(err)
	}
	if err := s.SeedDemo(vault); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.Nodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("expected 3 demo nodes, got %d", len(nodes))
	}
}
