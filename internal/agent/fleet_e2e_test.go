package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/store"
	webserver "github.com/252201/wukong-panel/internal/web"
)

type fleetE2EAgent struct{ *Manager }

func (a fleetE2EAgent) Import(ctx context.Context, fingerprints []string) error {
	_, err := a.Manager.Import(ctx, fingerprints)
	return err
}

func (a fleetE2EAgent) DeleteCandidate(ctx context.Context, id string, request model.CandidateDeleteRequest) error {
	return a.Manager.DeleteCandidate(ctx, id, request.ConfirmName)
}

func (a fleetE2EAgent) Action(ctx context.Context, id string, request model.NodeActionRequest) error {
	return a.Manager.Action(ctx, id, request.Action, request.ConfirmName)
}

func openFleetE2EStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	database, err := store.Open(filepath.Join(dir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func fleetE2ELogin(t *testing.T, client *http.Client, baseURL, password string) (*http.Cookie, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	response, err := client.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", response.StatusCode, data)
	}
	var result struct {
		CSRF string `json:"csrf"`
	}
	if err = json.Unmarshal(data, &result); err != nil || len(response.Cookies()) == 0 {
		t.Fatalf("invalid login response: %s", data)
	}
	return response.Cookies()[0], result.CSRF
}

func TestFleetDualInstanceEndToEnd(t *testing.T) {
	controllerDir := t.TempDir()
	controllerStore := openFleetE2EStore(t, controllerDir)
	initialPassword, _, err := controllerStore.EnsureAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if err = controllerStore.SetSetting("fleet_controller_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err = controllerStore.CreateFleetEnrollmentToken("e2e-enrollment", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	agentToken := "e2e-agent-token-with-at-least-32-bytes"
	host := model.FleetHost{ID: "remote-e2e", Name: "Remote E2E", Hostname: "remote-e2e", OS: "debian", Arch: "amd64", PanelVersion: "0.9.0", ProtocolVersion: model.FleetProtocolVersion, Capabilities: FleetCapabilities}
	if err = controllerStore.ConsumeFleetEnrollmentToken("e2e-enrollment", host, agentToken); err != nil {
		t.Fatal(err)
	}
	controllerVault, err := security.OpenVault(filepath.Join(controllerDir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	controllerManager := NewManager(config.Config{DataDir: controllerDir, SecretDir: filepath.Join(controllerDir, "secrets"), Demo: true}, controllerStore, controllerVault)
	controller := webserver.New(config.Config{DataDir: controllerDir, BasePath: "/", SecureCookie: false, Demo: true}, controllerStore, fleetE2EAgent{controllerManager}, "0.9.0")
	tlsServer := httptest.NewTLSServer(controller.Handler())
	defer tlsServer.Close()

	remoteDir := t.TempDir()
	remoteStore := openFleetE2EStore(t, remoteDir)
	remoteVault, err := security.OpenVault(filepath.Join(remoteDir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	remoteConfig := config.Config{DataDir: remoteDir, SecretDir: filepath.Join(remoteDir, "secrets"), Demo: true}
	remoteManager := NewManager(remoteConfig, remoteStore, remoteVault)
	connector := &FleetConnector{
		cfg: remoteConfig, client: FleetClientConfig{ControllerURL: tlsServer.URL + "/", HostID: host.ID, HostName: host.Name},
		token: agentToken, store: remoteStore, manager: remoteManager, version: "0.9.0", http: tlsServer.Client(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		connector.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("fleet connector did not stop")
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		connected, lookupErr := controllerStore.FleetHost(host.ID)
		if lookupErr == nil && connected.Online && connected.PanelVersion == "0.9.0" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("remote heartbeat not observed: host=%+v err=%v", connected, lookupErr)
		}
		time.Sleep(25 * time.Millisecond)
	}

	cookie, csrf := fleetE2ELogin(t, tlsServer.Client(), tlsServer.URL, initialPassword)
	passwordBody := []byte(`{"password":"fleet-e2e-password"}`)
	change, _ := http.NewRequest(http.MethodPost, tlsServer.URL+"/api/v1/auth/password", bytes.NewReader(passwordBody))
	change.Header.Set("Content-Type", "application/json")
	change.Header.Set("X-CSRF-Token", csrf)
	change.AddCookie(cookie)
	changeResponse, err := tlsServer.Client().Do(change)
	if err != nil {
		t.Fatal(err)
	}
	_ = changeResponse.Body.Close()
	if changeResponse.StatusCode != http.StatusOK {
		t.Fatalf("password change status=%d", changeResponse.StatusCode)
	}
	cookie, csrf = fleetE2ELogin(t, tlsServer.Client(), tlsServer.URL, "fleet-e2e-password")

	settings := model.Settings{Language: "zh-CN", Timezone: "Asia/Taipei", Interface: "auto", TrafficQuotaBytes: 987654321, BillingResetDay: 9, CollectEndpoints: false}
	settingsBody, _ := json.Marshal(settings)
	request, _ := http.NewRequest(http.MethodPut, tlsServer.URL+"/api/v1/fleet/hosts/"+host.ID+"/settings", bytes.NewReader(settingsBody))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(cookie)
	response, err := tlsServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("remote settings status=%d body=%s", response.StatusCode, data)
	}
	remoteSettings, err := remoteStore.Settings()
	if err != nil || remoteSettings.BillingResetDay != 9 || remoteSettings.TrafficQuotaBytes != 987654321 || remoteSettings.CollectEndpoints {
		t.Fatalf("remote settings=%+v err=%v", remoteSettings, err)
	}
	for label, database := range map[string]*store.Store{"controller": controllerStore, "remote": remoteStore} {
		var count int
		if err = database.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE actor='admin' AND action LIKE 'fleet.%'`).Scan(&count); err != nil || count == 0 {
			t.Fatalf("%s audit count=%d err=%v", label, count, err)
		}
	}
}
