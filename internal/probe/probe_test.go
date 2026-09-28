package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestJoinAndHeartbeatUseReadOnlyFleetProtocol(t *testing.T) {
	var enroll model.FleetEnrollmentRequest
	var heartbeat model.FleetHeartbeat
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fleet/api/v1/fleet/agent/enroll":
			if r.Method != http.MethodPost {
				t.Errorf("enroll method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&enroll); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"hostId":"host-1","agentToken":"secret","protocolVersion":1}`))
		case "/fleet/api/v1/fleet/agent/heartbeat":
			if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Wukong-Host-ID") != "host-1" {
				t.Errorf("missing heartbeat credentials")
			}
			if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	config, err := Join(context.Background(), directory, server.URL+"/fleet/", "one-time", "Probe VPS", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if config.HostID != "host-1" || enroll.Name != "Probe VPS" || enroll.Token != "one-time" || strings.Join(enroll.Capabilities, ",") != "overview,probe" || enroll.PanelVersion != "" {
		t.Fatalf("enrollment=%+v config=%+v", enroll, config)
	}
	for _, name := range []string{"config.json", "token"} {
		stat, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if stat.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o", name, stat.Mode().Perm())
		}
	}
	client, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP = server.Client()
	client.Version = "1.7.0"
	if err = client.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !heartbeat.Snapshot.Full || heartbeat.Snapshot.Overview.Now.Timestamp == 0 || heartbeat.Snapshot.Overview.NodeCount != 0 || len(heartbeat.Snapshot.Nodes) != 0 || heartbeat.PanelVersion != "1.7.0" || strings.Join(heartbeat.Capabilities, ",") != "overview,probe" {
		t.Fatalf("heartbeat=%+v", heartbeat)
	}
}

func TestJoinRequiresTrustedHTTPS(t *testing.T) {
	_, err := Join(context.Background(), t.TempDir(), "http://controller.example/fleet/", "token", "", nil)
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("error=%v", err)
	}
}
