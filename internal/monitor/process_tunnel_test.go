package monitor

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func TestCloudflaredNodeServices(t *testing.T) {
	services := cloudflaredNodeServices([]model.Node{
		{ID: "single", Name: "single node", Protocol: "vless-ws-tunnel", Ownership: "managed", ServiceManager: "systemd"},
		{ID: "phone", Name: "Phone", SharedGroup: "devices", Protocol: "vless-ws-tunnel", Ownership: "managed", ServiceManager: "openrc"},
		{ID: "tv", Name: "Apple TV", SharedGroup: "devices", Protocol: "vless-ws-tunnel", Ownership: "managed", ServiceManager: "openrc"},
		{ID: "external", Protocol: "vless-ws-tunnel", Ownership: "external", ServiceManager: "systemd"},
		{ID: "direct", Protocol: "hy2", Ownership: "managed", ServiceManager: "systemd"},
		{ID: "../../external", Protocol: "vless-ws-tunnel", Ownership: "managed", ServiceManager: "openrc"},
		{ID: "", Protocol: "vless-ws-tunnel", Ownership: "managed", ServiceManager: "openrc"},
	})
	want := map[string]tunnelProcessService{
		"cloudflared-wukong-single":  {manager: "systemd", nodes: []string{"single node"}},
		"cloudflared-wukong-devices": {manager: "openrc", nodes: []string{"Apple TV", "Phone"}},
	}
	if !reflect.DeepEqual(services, want) {
		t.Fatalf("unexpected connector ownership: %#v", services)
	}
}

func TestCloudflaredSystemdAssociation(t *testing.T) {
	services := map[string]tunnelProcessService{
		"cloudflared-wukong-one":    {manager: "systemd", nodes: []string{"one"}},
		"cloudflared-wukong-two":    {manager: "systemd", nodes: []string{"two"}},
		"cloudflared-wukong-openrc": {manager: "openrc", nodes: []string{"openrc"}},
	}
	for _, tt := range []struct {
		name, cgroup string
		want         []string
	}{
		{"v2", "0::/system.slice/cloudflared-wukong-one.service\n", []string{"one"}},
		{"v1", "5:memory:/unrelated\n1:name=systemd:/system.slice/cloudflared-wukong-two.service\n", []string{"two"}},
		{"external", "0::/system.slice/cloudflared.service\n", nil},
		{"suffix", "0::/system.slice/cloudflared-wukong-one.service-extra\n", nil},
		{"child", "0::/system.slice/cloudflared-wukong-one.service/another.scope\n", nil},
		{"controller", "5:memory:/system.slice/cloudflared-wukong-one.service\n", nil},
		{"wrong manager", "0::/system.slice/cloudflared-wukong-openrc.service\n", nil},
		{"malformed", "cloudflared-wukong-one.service\n", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := cloudflaredProcessNodes(42, []byte(tt.cgroup), services, t.TempDir())
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			if len(got) > 0 {
				got[0] = "modified"
				if services["cloudflared-wukong-one"].nodes[0] != "one" || services["cloudflared-wukong-two"].nodes[0] != "two" {
					t.Fatal("association mutated the stored ownership map")
				}
			}
		})
	}
}

func TestCloudflaredOpenRCAssociation(t *testing.T) {
	services := map[string]tunnelProcessService{
		"cloudflared-wukong-devices": {manager: "openrc", nodes: []string{"Apple TV", "Phone"}},
		"cloudflared-wukong-other":   {manager: "openrc", nodes: []string{"other"}},
		"cloudflared-wukong-systemd": {manager: "systemd", nodes: []string{"systemd"}},
	}
	for _, tt := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"shared", map[string]string{"devices": "42\n", "other": "99\n"}, []string{"Apple TV", "Phone"}},
		{"missing", nil, nil},
		{"wrong pid", map[string]string{"devices": "99\n"}, nil},
		{"invalid pid", map[string]string{"devices": "42 99\n"}, nil},
		{"conflicting", map[string]string{"devices": "42\n", "other": "42\n"}, nil},
		{"wrong manager", map[string]string{"systemd": "42\n"}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runDir := t.TempDir()
			for key, contents := range tt.files {
				if err := os.WriteFile(filepath.Join(runDir, "cloudflared-wukong-"+key+".pid"), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got := cloudflaredProcessNodes(42, nil, services, runDir)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// CI exercises the real Linux procfs collector, not just the classifier.
func TestProcessSnapshotLabelsCloudflared(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "cloudflared")
	script := filepath.Join(dir, "hold.sh")
	if err := os.Symlink("/bin/sh", binary); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, script)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	collector := &Collector{}
	for attempt := 0; attempt < 20; attempt++ {
		items, _ := collector.processSnapshot(1, nil, nil)
		for _, item := range items {
			if item.PID == command.Process.Pid {
				if item.Name != "cloudflared" || item.Service != "cloudflared" || len(item.Nodes) != 0 {
					t.Fatalf("unexpected external connector label: %#v", item)
				}
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("cloudflared missing from the process snapshot")
}
