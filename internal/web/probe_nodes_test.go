package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

func TestProbeNodesAPI(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().Unix()
	_, err = st.DB.Exec(`INSERT INTO fleet_hosts(id,name,hostname,os,arch,service_manager,panel_version,sing_box_version,protocol_version,capabilities_json,token_hash,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"probe-test-host", "Test Probe", "probe.example.com", "linux", "amd64", "systemd", "1.7.17", "", 1, `["probe","overview"]`, "hash", now, now)
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{store: st}
	dummySession := store.Session{Username: "admin"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/fleet/hosts/{hostId}/probe-nodes", func(w http.ResponseWriter, r *http.Request) {
		server.getFleetProbeNodes(w, r, dummySession)
	})
	mux.HandleFunc("POST /api/v1/fleet/hosts/{hostId}/probe-nodes", func(w http.ResponseWriter, r *http.Request) {
		server.createFleetProbeNode(w, r, dummySession)
	})
	mux.HandleFunc("PUT /api/v1/fleet/hosts/{hostId}/probe-nodes/{nodeId}", func(w http.ResponseWriter, r *http.Request) {
		server.updateFleetProbeNode(w, r, dummySession)
	})
	mux.HandleFunc("DELETE /api/v1/fleet/hosts/{hostId}/probe-nodes/{nodeId}", func(w http.ResponseWriter, r *http.Request) {
		server.deleteFleetProbeNode(w, r, dummySession)
	})

	// 1. Initial GET should return empty list
	req := httptest.NewRequest("GET", "/api/v1/fleet/hosts/probe-test-host/probe-nodes", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var nodes []model.FleetProbeNode
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(nodes))
	}

	// 2. POST single share link
	bodyData := []byte(`{"shareUri": "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@vpn.example.com:443?security=reality&pbk=pubkey&sid=sid1#US-Reality"}`)
	req = httptest.NewRequest("POST", "/api/v1/fleet/hosts/probe-test-host/probe-nodes", bytes.NewReader(bodyData))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var createdNodes []model.FleetProbeNode
	if err := json.Unmarshal(w.Body.Bytes(), &createdNodes); err != nil {
		t.Fatal(err)
	}
	if len(createdNodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(createdNodes))
	}
	createdNode := createdNodes[0]
	if createdNode.Name != "US-Reality" || createdNode.Protocol != "vless" || createdNode.Port != 443 {
		t.Fatalf("unexpected node: %+v", createdNode)
	}

	// 3. Rename node
	renameData := []byte(`{"name": "US-Fast-Reality"}`)
	req = httptest.NewRequest("PUT", "/api/v1/fleet/hosts/probe-test-host/probe-nodes/"+createdNode.ID, bytes.NewReader(renameData))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var renamedNode model.FleetProbeNode
	if err := json.Unmarshal(w.Body.Bytes(), &renamedNode); err != nil {
		t.Fatal(err)
	}
	if renamedNode.Name != "US-Fast-Reality" {
		t.Fatalf("expected US-Fast-Reality, got %s", renamedNode.Name)
	}

	// 4. DELETE node
	req = httptest.NewRequest("DELETE", "/api/v1/fleet/hosts/probe-test-host/probe-nodes/"+createdNode.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Verify empty again
	req = httptest.NewRequest("GET", "/api/v1/fleet/hosts/probe-test-host/probe-nodes", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	nodes = nil
	_ = json.Unmarshal(w.Body.Bytes(), &nodes)
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes after delete, got %d", len(nodes))
	}
}
