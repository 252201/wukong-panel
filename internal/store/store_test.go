package store

import (
	"database/sql"
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

func TestJobsOrdersNewestInsertionFirstWhenTimestampsMatch(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, err := s.CreateJob("node.create", "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateJob("node.delete", "second")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("UPDATE jobs SET created_at=?", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	items, err := s.Jobs(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != second.ID || items[1].ID != first.ID {
		t.Fatalf("jobs not ordered by newest insertion: %#v", items)
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
	if err := s.ReplaceEndpointWindow(now, 9*time.Second, []EndpointWindowSample{
		{NodeID: node.ID, NodeName: node.Name, Endpoint: "192.0.2.1:443", Bytes: 3_000},
		{NodeID: node.ID, NodeName: node.Name, Endpoint: "192.0.2.2:443", Bytes: 6_000},
	}); err != nil {
		t.Fatal(err)
	}
	devices, err := s.ActiveDevices(30*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].NodeName != node.Name || devices[0].Bytes != 9_000 || devices[0].RateBPS != 1_000 {
		t.Fatalf("unexpected device aggregation: %#v", devices)
	}
	if err := s.ReplaceEndpointWindow(now+1, 8*time.Second, nil); err != nil {
		t.Fatal(err)
	}
	devices, err = s.ActiveDevices(30*time.Second, 10)
	if err != nil || len(devices) != 0 {
		t.Fatalf("empty recent window did not clear active devices: %#v, %v", devices, err)
	}
}

func TestNodePersistsWebSocketPath(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node := model.Node{ID: "tunnel-route", Name: "iPhone", Protocol: "vless-ws-tunnel", Mode: "prefer_v6", ListenPort: 45116, Server: "shared.example.com", WebSocketPath: "/wukong-iphone", ServiceName: "sing-box-tunnel", ServiceManager: "systemd", ConfigPath: "/etc/s-box/tunnel.json", ConfigVersion: "1.13.14", Ownership: "managed", Status: "active"}
	if err := s.UpsertNode(t.Context(), node, "encrypted"); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Node(t.Context(), node.ID, false)
	if err != nil || stored.WebSocketPath != node.WebSocketPath {
		t.Fatalf("WebSocket path not persisted: %#v, %v", stored, err)
	}
	items, err := s.Nodes(t.Context())
	if err != nil || len(items) != 1 || items[0].WebSocketPath != node.WebSocketPath {
		t.Fatalf("WebSocket path not listed: %#v, %v", items, err)
	}
}

func TestRenameNodeSynchronizesTrafficNames(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node := model.Node{ID: "rename-me", Name: "旧名称", Protocol: "hysteria2", Mode: "prefer_v6", ListenPort: 45116, ServiceName: "sing-box-rename", ServiceManager: "systemd", ConfigPath: "/etc/s-box/rename.json", ConfigVersion: "1.13.14", Ownership: "managed", Status: "active"}
	if err := s.UpsertNode(t.Context(), node, "encrypted"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := s.ReplaceEndpointWindow(now, 10*time.Second, []EndpointWindowSample{{NodeID: node.ID, NodeName: node.Name, Endpoint: "192.0.2.1:443", Bytes: 1_000}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameNode(t.Context(), node.ID, "新名称"); err != nil {
		t.Fatal(err)
	}
	renamed, err := s.Node(t.Context(), node.ID, false)
	if err != nil || renamed.Name != "新名称" {
		t.Fatalf("node name not updated: %#v, %v", renamed, err)
	}
	devices, err := s.ActiveDevices(30*time.Second, 10)
	if err != nil || len(devices) != 1 || devices[0].NodeName != "新名称" {
		t.Fatalf("recent endpoint name not updated: %#v, %v", devices, err)
	}
	var dailyName string
	if err := s.DB.QueryRow("SELECT node_name FROM endpoint_daily WHERE node_id=?", node.ID).Scan(&dailyName); err != nil || dailyName != "新名称" {
		t.Fatalf("daily endpoint name not updated: %q, %v", dailyName, err)
	}
}

func TestUpdateNodeConfigVersionsTracksRuntimeVersion(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node := model.Node{ID: "legacy", Name: "Legacy", Protocol: "hysteria2", Mode: "v6only", ListenPort: 45119, ServiceName: "sing-box-legacy", ServiceManager: "openrc", ConfigPath: "/etc/s-box/legacy.json", ConfigVersion: "1.10.7", Ownership: "imported", Status: "active"}
	if err := s.UpsertNode(t.Context(), node, "encrypted"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateNodeConfigVersions("1.13.14"); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.Nodes(t.Context())
	if err != nil || len(nodes) != 1 || nodes[0].ConfigVersion != "1.13.14" {
		t.Fatalf("runtime version not synchronized: %#v, %v", nodes, err)
	}
}

func TestNodeProbeResultRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node := model.Node{ID: "probe-me", Name: "Probe", Protocol: "tuic", Mode: "prefer_v6", ListenPort: 45116, ServiceName: "sing-box-probe", ServiceManager: "systemd", ConfigPath: "/etc/s-box/probe.json", ConfigVersion: "1.13.14", Ownership: "managed", Status: "active"}
	if err = s.UpsertNode(t.Context(), node, "encrypted"); err != nil {
		t.Fatal(err)
	}
	checkedAt := time.Unix(1_789_000_000, 0)
	if err = s.SetNodeProbeResult(node.ID, "success", 87, "2001:db8::8", "www.cloudflare.com", "", checkedAt); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Node(t.Context(), node.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ProbeStatus != "success" || stored.ProbeLatencyMS != 87 || stored.ProbeExitIP != "2001:db8::8" || stored.ProbeTarget != "www.cloudflare.com" || !stored.ProbeCheckedAt.Equal(checkedAt) {
		t.Fatalf("unexpected probe result: %#v", stored)
	}
	items, err := s.Nodes(t.Context())
	if err != nil || len(items) != 1 || items[0].ProbeStatus != "success" {
		t.Fatalf("probe fields missing from node list: %#v err=%v", items, err)
	}
}

func TestPreferredServerRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node := model.Node{ID: "preferred", Name: "Preferred", Protocol: "vless-ws-tunnel", Mode: "prefer_v6", ListenPort: 45119, Server: "origin.example.com", Domain: "origin.example.com", PreferredServer: "preferred.example.com", ServiceName: "sing-box-preferred", ServiceManager: "systemd", ConfigPath: "/etc/s-box/preferred.json", ConfigVersion: "1.14", Ownership: "managed", Status: "active"}
	if err = s.UpsertNode(t.Context(), node, "encrypted"); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Node(t.Context(), node.ID, false)
	if err != nil || stored.PreferredServer != node.PreferredServer {
		t.Fatalf("preferred server not preserved: %#v err=%v", stored, err)
	}
	items, err := s.Nodes(t.Context())
	if err != nil || len(items) != 1 || items[0].PreferredServer != node.PreferredServer {
		t.Fatalf("preferred server missing from node list: %#v err=%v", items, err)
	}
}

func TestLegacyNodesSchemaAddsPreferredServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-nodes.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`CREATE TABLE nodes (
		id TEXT PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL, mode TEXT NOT NULL,
		listen_port INTEGER NOT NULL, server TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
		ipv4_bind TEXT NOT NULL DEFAULT '', ipv6_bind TEXT NOT NULL DEFAULT '', auto_bind INTEGER NOT NULL DEFAULT 1,
		service_name TEXT NOT NULL, service_manager TEXT NOT NULL, config_path TEXT NOT NULL,
		config_version TEXT NOT NULL, ownership TEXT NOT NULL, shared_group TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL, secret_cipher TEXT NOT NULL, probe_status TEXT NOT NULL DEFAULT '',
		probe_latency_ms INTEGER NOT NULL DEFAULT 0, probe_exit_ip TEXT NOT NULL DEFAULT '',
		probe_target TEXT NOT NULL DEFAULT '', probe_error TEXT NOT NULL DEFAULT '', probe_checked_at INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err = s.DB.QueryRow(`SELECT count(*) FROM pragma_table_info('nodes') WHERE name='preferred_server'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("preferred_server migration missing: count=%d err=%v", count, err)
	}
}

func TestReplaceProcessesPreservesCountAndOrdering(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	processes := []model.ProcessStat{
		{PID: 20, Name: "wukong-panel", CPU: 1.2, RSSBytes: 40_000_000, MemoryPercent: 2},
		{PID: 10, Name: "sing-box", CPU: 6.9, RSSBytes: 84_000_000, MemoryPercent: 4.2},
	}
	if err := s.ReplaceProcesses(time.Now().Unix(), 106, processes); err != nil {
		t.Fatal(err)
	}
	items, count, err := s.Processes(10)
	if err != nil || count != 106 || len(items) != 2 || items[0].Name != "sing-box" {
		t.Fatalf("unexpected processes: %#v count=%d err=%v", items, count, err)
	}
}

func TestMetricResourceTotalsRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	metric := model.Metric{Timestamp: time.Now().Unix(), Interface: "eth0", Memory: 50, MemoryUsedBytes: 1_000, MemoryTotalBytes: 2_000, Disk: 25, DiskUsedBytes: 2_500, DiskTotalBytes: 10_000}
	if err := s.AddMetric(metric); err != nil {
		t.Fatal(err)
	}
	items, err := s.Metrics(1)
	if err != nil || len(items) != 1 || items[0].MemoryUsedBytes != 1_000 || items[0].DiskTotalBytes != 10_000 {
		t.Fatalf("unexpected metric resource totals: %#v err=%v", items, err)
	}
}

func TestLegacyMetricsSchemaMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`CREATE TABLE metrics (
		ts INTEGER PRIMARY KEY, iface TEXT NOT NULL, rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL,
		rx_bps REAL NOT NULL, tx_bps REAL NOT NULL, cpu REAL NOT NULL, memory REAL NOT NULL,
		disk REAL NOT NULL, load1 REAL NOT NULL, uptime INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	metric := model.Metric{Timestamp: time.Now().Unix(), Interface: "eth0", MemoryUsedBytes: 1_000, MemoryTotalBytes: 2_000, DiskUsedBytes: 2_500, DiskTotalBytes: 10_000}
	if err = s.AddMetric(metric); err != nil {
		t.Fatal(err)
	}
	items, err := s.Metrics(1)
	if err != nil || len(items) != 1 || items[0].MemoryTotalBytes != 2_000 || items[0].DiskUsedBytes != 2_500 {
		t.Fatalf("legacy migration did not preserve resource totals: %#v err=%v", items, err)
	}
}
