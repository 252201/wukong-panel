package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
)

func baseRequest() model.NodeCreateRequest {
	return model.NodeCreateRequest{Name: "Test", Mode: "prefer_v6", IPv4Bind: "192.0.2.5", IPv6Bind: "2001:db8::5", V6OnlyDomains: []string{"chatgpt.com"}}
}

func TestBuildLegacyConfig(t *testing.T) {
	payload, err := buildConfig(baseRequest(), 45080, "secret", "/tmp/cert", "/tmp/key", "1.10.7")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	if !strings.Contains(text, `"domain_strategy": "prefer_ipv6"`) {
		t.Fatal("legacy domain strategy missing")
	}
	if strings.Contains(text, `"domain_resolver"`) {
		t.Fatal("legacy config contains modern resolver")
	}
}

func TestBuildModernConfig(t *testing.T) {
	payload, err := buildConfig(baseRequest(), 45080, "secret", "/tmp/cert", "/tmp/key", "1.14.0")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	if root["dns"] == nil {
		t.Fatal("modern DNS configuration missing")
	}
	text := string(payload)
	if !strings.Contains(text, `"domain_resolver"`) || !strings.Contains(text, `"action": "sniff"`) {
		t.Fatal("modern migration fields missing")
	}
	if strings.Contains(text, `"domain_strategy"`) {
		t.Fatal("modern config contains removed domain_strategy")
	}
}

func TestValidateCreateRejectsUnsafeValues(t *testing.T) {
	request := baseRequest()
	request.Mode = "unknown"
	if validateCreate(request) == nil {
		t.Fatal("invalid mode accepted")
	}
	request = baseRequest()
	request.IPv4Bind = "$(touch /tmp/nope)"
	if validateCreate(request) == nil {
		t.Fatal("invalid IP accepted")
	}
}

func TestCertificatePathsReuseTrustedPanelCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "panel.cer")
	keyPath := filepath.Join(dir, "panel.key")
	if err := generateSelfSigned(keyPath, certPath, "node.example.com"); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{cfg: config.Config{ConfigDir: dir, TLSCertFile: certPath, TLSKeyFile: keyPath}}
	request := baseRequest()
	request.Domain = "node.example.com"
	cert, key, generate, err := manager.certificatePaths(request, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cert != certPath || key != keyPath || generate {
		t.Fatalf("trusted certificate not reused: cert=%s key=%s generate=%v", cert, key, generate)
	}
}

func TestCertificatePathsFallBackWhenDomainDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "panel.cer")
	keyPath := filepath.Join(dir, "panel.key")
	if err := generateSelfSigned(keyPath, certPath, "panel.example.com"); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{cfg: config.Config{ConfigDir: dir, TLSCertFile: certPath, TLSKeyFile: keyPath}}
	request := baseRequest()
	request.Domain = "node.example.com"
	cert, key, generate, err := manager.certificatePaths(request, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cert != filepath.Join(dir, "wukong-test.cer") || key != filepath.Join(dir, "wukong-test.key") || !generate {
		t.Fatalf("expected self-signed fallback: cert=%s key=%s generate=%v", cert, key, generate)
	}
}

func TestGeneratedSelfSignedCertificateHasSAN(t *testing.T) {
	dir := t.TempDir()
	for _, domain := range []string{"node.example.com", "2001:db8::10"} {
		certPath := filepath.Join(dir, strings.NewReplacer(":", "-", ".", "-").Replace(domain)+".cer")
		keyPath := certPath + ".key"
		if err := generateSelfSigned(keyPath, certPath, domain); err != nil {
			t.Fatal(err)
		}
		if !certificateCoversDomain(certPath, domain) {
			t.Fatalf("generated certificate does not cover %s", domain)
		}
	}
}

func TestExplicitCertificateMustCoverTLSDomain(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "panel.cer")
	keyPath := filepath.Join(dir, "panel.key")
	if err := generateSelfSigned(keyPath, certPath, "panel.example.com"); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{cfg: config.Config{ConfigDir: dir}}
	request := baseRequest()
	request.Domain = "node.example.com"
	request.CertificatePath = certPath
	request.KeyPath = keyPath
	if _, _, _, err := manager.certificatePaths(request, "test"); err == nil {
		t.Fatal("mismatched explicit certificate accepted")
	}
}

func TestSelfSignedNodeConfigIsDetectedForShareLink(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.cer")
	keyPath := filepath.Join(dir, "node.key")
	if err := generateSelfSigned(keyPath, certPath, "node.example.com"); err != nil {
		t.Fatal(err)
	}
	payload, err := buildConfig(baseRequest(), 45080, "secret", certPath, keyPath, "1.10.7")
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "node.json")
	if err = os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if !configUsesSelfSignedCertificate(configPath) {
		t.Fatal("self-signed node certificate was not detected")
	}
}
