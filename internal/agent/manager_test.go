package agent

import (
	"encoding/json"
	"strings"
	"testing"

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
