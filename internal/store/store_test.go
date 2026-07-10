package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
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

func TestActiveDevicesAggregatesRecentNodeTraffic(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node := model.Node{ID: "mac-mini", Name: "Mac mini", Protocol: "hysteria2", Mode: "prefer_v6", ListenPort: 45116, ServiceName: "sing-box-devices", ServiceManager: "systemd", ConfigPath: "/etc/s-box/devices.json", ConfigVersion: "1.10", Ownership: "imported", Status: "active"}
	if err := s.UpsertNode(t.Context(), node, "encrypted"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := s.AddEndpointSample(now, node.ID, node.Name, "192.0.2.1:443", 3_000); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEndpointSample(now, node.ID, node.Name, "192.0.2.2:443", 6_000); err != nil {
		t.Fatal(err)
	}
	devices, err := s.ActiveDevices(30*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].NodeName != node.Name || devices[0].Bytes != 9_000 || devices[0].RateBPS != 300 {
		t.Fatalf("unexpected device aggregation: %#v", devices)
	}
}
