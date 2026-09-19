package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func openFleetTestStore(t *testing.T) *Store {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestFleetEnrollmentTokenSingleUseExpiryAndRevocation(t *testing.T) {
	database := openFleetTestStore(t)
	host := model.FleetHost{ID: "host-a", Name: "A", ProtocolVersion: model.FleetProtocolVersion, Capabilities: []string{"overview"}}
	if err := database.CreateFleetEnrollmentToken("once", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ConsumeFleetEnrollmentToken("once", host, "agent-secret"); err != nil {
		t.Fatal(err)
	}
	if !database.AuthenticateFleetHost(host.ID, "agent-secret") || database.AuthenticateFleetHost(host.ID, "wrong") {
		t.Fatal("agent token authentication mismatch")
	}
	host.ID = "host-b"
	if err := database.ConsumeFleetEnrollmentToken("once", host, "second"); err == nil {
		t.Fatal("one-time enrollment token was reused")
	}
	if err := database.CreateFleetEnrollmentToken("expired", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.ConsumeFleetEnrollmentToken("expired", host, "second"); err == nil {
		t.Fatal("expired enrollment token was accepted")
	}
	if err := database.ArchiveFleetHost("host-a"); err != nil {
		t.Fatal(err)
	}
	if database.AuthenticateFleetHost("host-a", "agent-secret") {
		t.Fatal("archived host credential remained active")
	}
}

func TestFleetHeartbeatMergeMetricsAndProtocolCompatibility(t *testing.T) {
	database := openFleetTestStore(t)
	if err := database.CreateFleetEnrollmentToken("once", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	host := model.FleetHost{ID: "host-a", Name: "A", ProtocolVersion: model.FleetProtocolVersion}
	if err := database.ConsumeFleetEnrollmentToken("once", host, "token"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	full := model.FleetHeartbeat{ProtocolVersion: model.FleetProtocolVersion, PanelVersion: "0.9.0", Snapshot: model.FleetSnapshot{Full: true, Overview: model.Overview{Now: model.Metric{Timestamp: now, CPU: 12}}, Nodes: []model.Node{{ID: "n1", Name: "Node", Protocol: "vless", Status: "active"}}}}
	if err := database.SaveFleetHeartbeat(context.Background(), host.ID, full); err != nil {
		t.Fatal(err)
	}
	fast := model.FleetHeartbeat{ProtocolVersion: model.FleetProtocolVersion, Snapshot: model.FleetSnapshot{Overview: model.Overview{Now: model.Metric{Timestamp: now + 10, CPU: 33}}, Nodes: []model.Node{{ID: "n1", Status: "inactive"}}}}
	if err := database.SaveFleetHeartbeat(context.Background(), host.ID, fast); err != nil {
		t.Fatal(err)
	}
	stored, err := database.FleetHost(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Compatible || stored.Snapshot.Nodes[0].Protocol != "vless" || stored.Snapshot.Nodes[0].Status != "inactive" {
		t.Fatalf("fast heartbeat did not merge with slow snapshot: %+v", stored)
	}
	metrics, err := database.FleetMetrics(host.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 2 || metrics[1].Timestamp != now+10 {
		t.Fatalf("metrics=%+v", metrics)
	}
}

func TestFleetCommandRedeliveryReceiptAndExpiry(t *testing.T) {
	database := openFleetTestStore(t)
	if err := database.CreateFleetEnrollmentToken("once", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ConsumeFleetEnrollmentToken("once", model.FleetHost{ID: "host-a", Name: "A", ProtocolVersion: 1}, "token"); err != nil {
		t.Fatal(err)
	}
	command, err := database.QueueFleetCommand("host-a", "", "node.rename", "admin", "cipher", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	first, err := database.NextFleetCommand("host-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := database.NextFleetCommand("host-a")
	if err != nil {
		t.Fatal(err)
	}
	if first.Command.ID != command.ID || second.Command.ID != command.ID {
		t.Fatal("running command was not redelivered with the same id")
	}
	result, _ := json.Marshal(map[string]bool{"ok": true})
	if err := database.SaveFleetReceipt(command.ID, "success", string(result), ""); err != nil {
		t.Fatal(err)
	}
	receipt, err := database.FleetReceipt(command.ID)
	if err != nil || receipt.Status != "success" {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	if _, err = database.CompleteFleetCommand(command.ID, "success", "sealed", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = database.NextFleetCommand("host-a"); err != sql.ErrNoRows {
		t.Fatalf("next after completion err=%v", err)
	}
	expired, err := database.QueueFleetCommand("host-a", "", "node.edit", "admin", "cipher", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.NextFleetCommand("host-a"); err != sql.ErrNoRows {
		t.Fatalf("expired command became executable: %v", err)
	}
	status, _, _, err := database.FleetCommand(expired.ID)
	if err != nil || status != "expired" {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

func TestFleetMigrationIsAdditiveToSingleHostData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v082.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = database.EnsureAdmin(); err != nil {
		t.Fatal(err)
	}
	node := model.Node{ID: "legacy-node", Name: "Legacy", Protocol: "vless", Mode: "v4only", Egress: "direct", ListenPort: 34001, ServiceName: "sing-box-legacy", ServiceManager: "systemd", ConfigPath: "/etc/s-box/legacy.json", ConfigVersion: "1.13.14", Ownership: "managed", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err = database.UpsertNode(context.Background(), node, "sealed-legacy-secret"); err != nil {
		t.Fatal(err)
	}
	if err = database.AddMetric(model.Metric{Timestamp: time.Now().Unix(), Interface: "eth0", CPU: 9}); err != nil {
		t.Fatal(err)
	}
	job, err := database.CreateJob("node.check", node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.SetSetting("subscription_token", "legacy-subscription"); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"fleet_subscription_cache", "fleet_command_receipts", "fleet_commands", "fleet_metrics", "fleet_hosts", "fleet_enrollment_tokens"} {
		if _, err = raw.Exec("DROP TABLE " + table); err != nil {
			t.Fatal(err)
		}
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	stored, err := upgraded.Node(context.Background(), node.ID, false)
	if err != nil || stored.Name != "Legacy" {
		t.Fatalf("node=%+v err=%v", stored, err)
	}
	if _, err = upgraded.Job(job.ID); err != nil {
		t.Fatal("legacy job was lost:", err)
	}
	if token, _ := upgraded.Setting("subscription_token"); token != "legacy-subscription" {
		t.Fatalf("subscription=%q", token)
	}
	if _, err = upgraded.FleetHosts(false); err != nil {
		t.Fatal("fleet schema missing after upgrade:", err)
	}
}
