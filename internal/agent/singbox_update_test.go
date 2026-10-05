package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/252201/wukong-panel/internal/componentupdate"
	"github.com/252201/wukong-panel/internal/model"
)

func TestSingBoxUpdatePreparationMigratesWithoutTouchingLiveFiles(t *testing.T) {
	m, db := newDemoManager(t)
	os.MkdirAll(m.cfg.ConfigDir, 0700)
	path := filepath.Join(m.cfg.ConfigDir, "node.json")
	original := []byte(`{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":19239,"sniff":true}],"outbounds":[{"type":"direct"}]}`)
	os.WriteFile(path, original, 0600)
	n := model.Node{ID: "one", Ownership: "managed", ConfigPath: path, ServiceName: "sing-box-wukong-one", ServiceManager: "systemd", Protocol: "socks5"}
	if e := db.UpsertNode(t.Context(), n, ""); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(t.TempDir(), "candidate")
	// The candidate rejects any configuration which still contains a legacy field.
	os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = check ]; then ! grep -q '\"sniff\":' \"$3\"; else exit 1; fi\n"), 0755)
	files, e := m.prepareSingBoxUpdate(t.Context(), binary, "1.14.2")
	if e != nil || len(files) != 1 {
		t.Fatal(files, e)
	}
	if !bytes.Equal(files[0].Old, original) || bytes.Contains(files[0].New, []byte(`"sniff":`)) {
		t.Fatal("migration snapshot wrong")
	}
	live, _ := os.ReadFile(path)
	if !bytes.Equal(live, original) {
		t.Fatal("preparation changed live files")
	}
	os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0755)
	if _, e = m.prepareSingBoxUpdate(t.Context(), binary, "1.14.2"); e == nil {
		t.Fatal("candidate rejection was ignored")
	}
	os.WriteFile(filepath.Join(m.cfg.ConfigDir, "external.json"), []byte(`{}`), 0600)
	if _, e = m.ownedSingBoxConfigs(context.Background()); e == nil {
		t.Fatal("unmanaged config accepted")
	}
	os.Remove(filepath.Join(m.cfg.ConfigDir, "external.json"))
	os.Remove(path)
	os.Symlink(binary, path)
	if _, e = m.ownedSingBoxConfigs(t.Context()); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestSingBoxSupportedTargetProfile(t *testing.T) {
	m, _ := newDemoManager(t)
	c := m.singBoxUpdater()
	for _, v := range []string{"1.14.1", "1.14.2", "1.14.99"} {
		if !c.AllowedTarget(v) {
			t.Fatal("supported patch blocked", v)
		}
	}
	for _, v := range []string{"1.15.0", "2.0.0", "1.13.14", "1.14.2-beta"} {
		if c.AllowedTarget(v) {
			t.Fatal("unsupported profile allowed", v)
		}
	}
}

func TestSingBoxRecoverySkipsAlreadyStoppedOpenRCService(t *testing.T) {
	m, _ := newDemoManager(t)
	m.cfg.Demo = false
	dir := t.TempDir()
	marker := filepath.Join(dir, "stop-called")
	script := "#!/bin/sh\nif [ \"$2\" = status ]; then exit 1; fi\nprintf called > " + marker + "\nexit 1\n"
	if e := os.WriteFile(filepath.Join(dir, "rc-service"), []byte(script), 0755); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if e := m.singBoxUpdater().Stop(t.Context(), componentupdate.Service{Name: "sing-box-wukong-test", Manager: "openrc"}); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("inactive service was stopped again")
	}
}
