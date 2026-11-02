package store

import (
	"path/filepath"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestChainedProxyStore(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer st.Close()

	// Initial query should return empty slice
	list, err := st.ChainedProxies()
	if err != nil {
		t.Fatalf("ChainedProxies error: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 chained proxies, got %d", len(list))
	}

	// Validation: cannot have empty IDs or same entry/exit
	if err := st.SaveChainedProxy(model.ChainedProxy{ID: "cp1", EntryNodeName: "NodeA", ExitNodeName: "NodeA"}); err == nil {
		t.Fatal("expected error when entry and exit are the same")
	}

	// Insert valid chained proxy
	cp1 := model.ChainedProxy{
		ID:            "cp1",
		Name:          "🔗 香港 ➔ 土耳其",
		EntryNodeName: "🇭🇰 香港 01",
		ExitNodeName:  "🇹🇷 土耳其 01",
		Enabled:       true,
	}
	if err := st.SaveChainedProxy(cp1); err != nil {
		t.Fatalf("SaveChainedProxy error: %v", err)
	}

	list, err = st.ChainedProxies()
	if err != nil {
		t.Fatalf("ChainedProxies error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 chained proxy, got %d", len(list))
	}
	if list[0].Name != "🔗 香港 ➔ 土耳其" || !list[0].Enabled {
		t.Fatalf("unexpected chained proxy data: %+v", list[0])
	}

	// Toggle
	if err := st.ToggleChainedProxy("cp1", false); err != nil {
		t.Fatalf("ToggleChainedProxy error: %v", err)
	}
	list, err = st.ChainedProxies()
	if err != nil {
		t.Fatalf("ChainedProxies error: %v", err)
	}
	if list[0].Enabled {
		t.Fatal("expected chained proxy to be disabled")
	}

	// Update name
	cp1.Name = "🔗 自建香港 ➔ 土耳其解锁"
	cp1.Enabled = true
	if err := st.SaveChainedProxy(cp1); err != nil {
		t.Fatalf("SaveChainedProxy update error: %v", err)
	}
	list, _ = st.ChainedProxies()
	if list[0].Name != "🔗 自建香港 ➔ 土耳其解锁" || !list[0].Enabled {
		t.Fatalf("unexpected updated data: %+v", list[0])
	}

	// Delete
	if err := st.DeleteChainedProxy("cp1"); err != nil {
		t.Fatalf("DeleteChainedProxy error: %v", err)
	}
	list, _ = st.ChainedProxies()
	if len(list) != 0 {
		t.Fatalf("expected 0 chained proxies after deletion, got %d", len(list))
	}
}
