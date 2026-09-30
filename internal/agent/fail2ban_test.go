package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func TestFail2banRootSocketAccessAndLifecycle(t *testing.T) {
	manager, _ := newDemoManager(t)
	dir, err := os.MkdirTemp("/tmp", "wk-agent-f2b-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- NewServer(manager, "test-agent-token", nil).ListenAndServe(ctx, socket) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("Agent did not stop")
		}
	})
	client := NewClient(socket, "test-agent-token")
	defer client.http.CloseIdleConnections()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err = client.Fail2ban(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	wrong := NewClient(socket, "wrong-token")
	defer wrong.http.CloseIdleConnections()
	if _, err = wrong.Fail2ban(ctx); err == nil {
		t.Fatal("status accepted bad Agent token")
	}
	r := model.Fail2banConfig{Enabled: true, MaxRetry: 5, FindTime: 600, BanTime: 3600, Mode: "normal", IgnoreIPs: []string{"203.0.113.7"}}
	if _, err = wrong.ConfigureFail2ban(ctx, r); err == nil {
		t.Fatal("write accepted bad Agent token")
	}
	got, err := client.ConfigureFail2ban(ctx, r)
	if err != nil || !got.Active || len(got.BannedIPs) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err = wrong.UnbanFail2ban(ctx, model.Fail2banUnbanRequest{IP: "192.0.2.47"}); err == nil {
		t.Fatal("unban accepted bad token")
	}
	got, err = client.UnbanFail2ban(ctx, model.Fail2banUnbanRequest{IP: "192.0.2.47"})
	if err != nil || len(got.BannedIPs) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	r.Enabled = false
	got, err = client.ConfigureFail2ban(ctx, r)
	if err != nil || got.Active {
		t.Fatalf("%+v %v", got, err)
	}
}
