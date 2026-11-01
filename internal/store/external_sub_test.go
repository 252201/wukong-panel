package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestExternalSubscriptionCRUD(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Initial list should be empty
	subs, err := db.ExternalSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 0 {
		t.Fatalf("expected 0 subs, got %d", len(subs))
	}

	// Create a new subscription
	sub1 := model.ExternalSubscription{
		ID:                "sub-1",
		Name:              "My Airport",
		URL:               "https://airport.example.com/sub",
		ProxyURL:          "http://127.0.0.1:2080",
		RawContent:        "proxies:\n  - name: test\n    type: trojan\n    server: hk.test\n    port: 443",
		UserAgent:         "ClashMeta",
		Enabled:           true,
		AutoSync:          true,
		SyncIntervalHours: 6,
		Nodes: []model.Node{
			{
				ID:         "ext-node-1",
				Name:       "HK Node 1",
				Protocol:   "vless",
				Server:     "hk.example.com",
				ListenPort: 443,
				Status:     "active",
				ShareURI:   "vless://uuid@hk.example.com:443?security=reality#HK%20Node%201",
			},
		},
		SelectedNodeIDs: []string{"ext-node-1"},
	}

	if err := db.SaveExternalSubscription(sub1); err != nil {
		t.Fatalf("SaveExternalSubscription failed: %v", err)
	}

	// Read it back
	got, err := db.ExternalSubscription("sub-1")
	if err != nil {
		t.Fatalf("ExternalSubscription failed: %v", err)
	}
	if got.Name != "My Airport" || got.URL != "https://airport.example.com/sub" || got.ProxyURL != "http://127.0.0.1:2080" || got.RawContent != sub1.RawContent || !got.Enabled || !got.AutoSync {
		t.Fatalf("unexpected subscription content: %+v", got)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].Name != "HK Node 1" || got.Nodes[0].ShareURI != sub1.Nodes[0].ShareURI {
		t.Fatalf("unexpected nodes: %+v", got.Nodes)
	}
	if len(got.SelectedNodeIDs) != 1 || got.SelectedNodeIDs[0] != "ext-node-1" {
		t.Fatalf("unexpected selected node ids: %+v", got.SelectedNodeIDs)
	}

	// Update sync result
	nodesUpdated := []model.Node{
		{
			ID:         "ext-node-1",
			Name:       "HK Node 1",
			Protocol:   "vless",
			Server:     "hk.example.com",
			ListenPort: 443,
			Status:     "active",
			ShareURI:   "vless://uuid@hk.example.com:443?security=reality#HK%20Node%201",
		},
		{
			ID:         "ext-node-2",
			Name:       "SG Node 2",
			Protocol:   "hysteria2",
			Server:     "sg.example.com",
			ListenPort: 443,
			Status:     "active",
			ShareURI:   "hysteria2://pass@sg.example.com:443/#SG%20Node%202",
		},
	}
	err = db.UpdateExternalSubscriptionSyncResult("sub-1", 1024, 2048, 100000, "2026-12-31", nodesUpdated, nil)
	if err != nil {
		t.Fatalf("UpdateExternalSubscriptionSyncResult failed: %v", err)
	}

	gotAfterSync, err := db.ExternalSubscription("sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotAfterSync.UploadBytes != 1024 || gotAfterSync.DownloadBytes != 2048 || gotAfterSync.TotalBytes != 100000 {
		t.Fatalf("unexpected traffic stats: %+v", gotAfterSync)
	}
	if gotAfterSync.ExpiresAt != "2026-12-31" {
		t.Fatalf("unexpected expiresAt: %s", gotAfterSync.ExpiresAt)
	}
	if len(gotAfterSync.Nodes) != 2 {
		t.Fatalf("expected 2 nodes after sync, got %d", len(gotAfterSync.Nodes))
	}
	if gotAfterSync.LastSyncAt.IsZero() {
		t.Fatal("expected LastSyncAt to be set")
	}

	// Update sync result with error and empty nodes (simulating real fetch failure)
	syncErr := errors.New("timeout fetching subscription")
	err = db.UpdateExternalSubscriptionSyncResult("sub-1", 0, 0, 0, "", nil, syncErr)
	if err != nil {
		t.Fatal(err)
	}
	gotAfterErr, _ := db.ExternalSubscription("sub-1")
	if gotAfterErr.LastError != "timeout fetching subscription" {
		t.Fatalf("expected last error recorded, got: %s", gotAfterErr.LastError)
	}
	// Verify that existing nodes and quotas were preserved despite transient error
	if len(gotAfterErr.Nodes) != 2 {
		t.Fatalf("expected nodes to be preserved on sync error, got %d", len(gotAfterErr.Nodes))
	}
	if gotAfterErr.TotalBytes != 100000 || gotAfterErr.ExpiresAt != "2026-12-31" {
		t.Fatalf("expected traffic/expiry to be preserved, got total=%d, expire=%s", gotAfterErr.TotalBytes, gotAfterErr.ExpiresAt)
	}

	// Delete
	if err := db.DeleteExternalSubscription("sub-1"); err != nil {
		t.Fatalf("DeleteExternalSubscription failed: %v", err)
	}
	_, err = db.ExternalSubscription("sub-1")
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestExternalSubscriptionNilNodesSafe(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Sub with nil Nodes and SelectedNodeIDs
	sub := model.ExternalSubscription{
		ID:   "sub-nil-nodes",
		Name: "Empty Airport",
		URL:  "https://airport.invalid/sub",
	}
	if err := db.SaveExternalSubscription(sub); err != nil {
		t.Fatalf("SaveExternalSubscription failed: %v", err)
	}

	got, err := db.ExternalSubscription("sub-nil-nodes")
	if err != nil {
		t.Fatalf("ExternalSubscription failed: %v", err)
	}
	if got.Nodes == nil {
		t.Fatalf("expected got.Nodes to be non-nil empty slice, got nil")
	}
	if got.SelectedNodeIDs == nil {
		t.Fatalf("expected got.SelectedNodeIDs to be non-nil empty slice, got nil")
	}

	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"nodes":[]`) {
		t.Fatalf("expected serialized JSON to contain \"nodes\":[], got: %s", string(data))
	}

	// Also verify ExternalSubscriptions() list
	list, err := db.ExternalSubscriptions()
	if err != nil {
		t.Fatalf("ExternalSubscriptions failed: %v", err)
	}
	if len(list) != 1 || list[0].Nodes == nil {
		t.Fatalf("expected 1 sub with non-nil nodes in list, got %+v", list)
	}
}

func TestExternalSubscriptionSelectedNodesPruning(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sub := model.ExternalSubscription{
		ID:   "sub-prune",
		Name: "Prune Airport",
		URL:  "https://airport.invalid/sub",
		Nodes: []model.Node{
			{ID: "node-1", Name: "HK 1", Protocol: "trojan", Server: "hk1.com", ListenPort: 443},
			{ID: "node-2", Name: "HK 2", Protocol: "trojan", Server: "hk2.com", ListenPort: 443},
		},
		SelectedNodeIDs: []string{"node-1", "node-deleted-1", "node-deleted-2"},
	}
	if err := db.SaveExternalSubscription(sub); err != nil {
		t.Fatalf("SaveExternalSubscription failed: %v", err)
	}

	// Retrieval should automatically prune obsolete IDs
	got, err := db.ExternalSubscription("sub-prune")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SelectedNodeIDs) != 1 || got.SelectedNodeIDs[0] != "node-1" {
		t.Fatalf("expected obsolete node IDs pruned, got %+v", got.SelectedNodeIDs)
	}

	// UpdateExternalSubscriptionSyncResult with new node set
	newNodes := []model.Node{
		{ID: "node-2", Name: "HK 2", Protocol: "trojan", Server: "hk2.com", ListenPort: 443},
		{ID: "node-3", Name: "SG 1", Protocol: "trojan", Server: "sg1.com", ListenPort: 443},
	}
	err = db.UpdateExternalSubscriptionSyncResult("sub-prune", 100, 200, 1000, "2027-01-01", newNodes, nil)
	if err != nil {
		t.Fatal(err)
	}

	gotAfterSync, err := db.ExternalSubscription("sub-prune")
	if err != nil {
		t.Fatal(err)
	}
	// "node-1" is no longer in newNodes, so SelectedNodeIDs should now have 0 matching IDs
	if len(gotAfterSync.SelectedNodeIDs) != 0 {
		t.Fatalf("expected all obsolete selected IDs pruned, got %+v", gotAfterSync.SelectedNodeIDs)
	}
}
