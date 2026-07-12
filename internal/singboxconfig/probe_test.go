package singboxconfig

import (
	"encoding/json"
	"testing"
)

func TestBuildHY2Probe(t *testing.T) {
	inbound := map[string]any{"type": "hysteria2", "listen": "::", "listen_port": float64(443), "users": []any{map[string]any{"password": "secret"}}}
	data, err := buildHY2Probe(inbound, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if json.Unmarshal(data, &root) != nil {
		t.Fatal("probe config is invalid JSON")
	}
	outbound := root["outbounds"].([]any)[0].(map[string]any)
	if outbound["server"] != "::1" || outbound["password"] != "secret" {
		t.Fatalf("unexpected probe outbound: %+v", outbound)
	}
}

func TestBuildHY2ProbeRequiresPassword(t *testing.T) {
	_, err := buildHY2Probe(map[string]any{"listen_port": float64(443)}, "", "")
	if err == nil {
		t.Fatal("missing password accepted")
	}
}

func TestBuildHY2ProbeServerOverride(t *testing.T) {
	inbound := map[string]any{"listen": "::", "listen_port": float64(443), "users": []any{map[string]any{"password": "secret"}}}
	data, err := buildHY2Probe(inbound, "node.example.com", "node.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	_ = json.Unmarshal(data, &root)
	outbound := root["outbounds"].([]any)[0].(map[string]any)
	if outbound["server"] != "node.example.com" || outbound["tls"].(map[string]any)["insecure"] != false {
		t.Fatalf("server override ignored: %+v", outbound)
	}
}
