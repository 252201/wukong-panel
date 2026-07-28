package agent

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestResidentialRequestNormalizesNodeToMarkedIPv4(t *testing.T) {
	request := baseRequest()
	request.Egress = "residential"
	request.AutoBind = true
	request = normalizeModeBindings(request)
	if request.Mode != "v4only" || request.IPv4Bind != "" || request.IPv6Bind != "" || request.AutoBind {
		t.Fatalf("residential request was not normalized: %#v", request)
	}
	payload, err := buildConfig(request, 45080, protocolCredentials{Password: "secret"}, "/tmp/cert", "/tmp/key", "1.13.14")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	outbound := root["outbounds"].([]any)[0].(map[string]any)
	if outbound["routing_mark"] != float64(residentialRouteMark) {
		t.Fatalf("residential routing mark missing: %#v", outbound)
	}
	if outbound["inet4_bind_address"] != nil || outbound["inet6_bind_address"] != nil {
		t.Fatalf("residential outbound contains a source bind: %#v", outbound)
	}
	resolver := outbound["domain_resolver"].(map[string]any)
	if resolver["strategy"] != "ipv4_only" {
		t.Fatalf("residential resolver is not IPv4-only: %#v", resolver)
	}
}

func TestResidentialPeerScriptKeepsPeerPrivateKeyLocal(t *testing.T) {
	privateKey, publicKey, err := wireGuardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	state := residentialExitState{
		Endpoint: "a.example.com", ListenPort: 51820,
		PrivateKey: privateKey, PublicKey: publicKey,
	}
	script := renderResidentialPeerScript(state)
	if strings.Contains(script, privateKey) {
		t.Fatal("A private key leaked into the B install script")
	}
	for _, want := range []string{"PRIVATE_KEY=\"$(wg genkey)\"", "B_PUBLIC_KEY=$PUBLIC_KEY", "Endpoint = a.example.com:51820", "PublicKey = " + publicKey, "MASQUERADE", "--remove-residential-peer"} {
		if !strings.Contains(script, want) {
			t.Fatalf("B install script is missing %q", want)
		}
	}
	if !strings.Contains(script, "sysctl -w net.ipv4.ip_forward=1") {
		t.Fatal("B install script does not apply the required IPv4 forwarding setting directly")
	}
	if strings.Contains(script, "sysctl --system") {
		t.Fatal("B install script loads unrelated sysctl settings")
	}
	if !strings.Contains(script, `OUT_IF="\$(ip -4 route`) || !strings.Contains(script, `"\$OUT_IF"`) {
		t.Fatal("B script would expand the NAT interface variables while writing its WireGuard config")
	}
	path := filepath.Join(t.TempDir(), "install-peer.sh")
	if err = os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, syntaxErr := exec.Command("sh", "-n", path).CombinedOutput(); syntaxErr != nil {
		t.Fatalf("B install script has invalid shell syntax: %v\n%s", syntaxErr, output)
	}
}

func TestResidentialGuardIsFailClosed(t *testing.T) {
	guard := renderResidentialGuardScript()
	for _, want := range []string{
		"route replace unreachable default",
		"fwmark 102/0xffffffff lookup 166",
		"route flush table 166",
	} {
		if !strings.Contains(guard, want) {
			t.Fatalf("guard script is missing %q", want)
		}
	}
	local := renderResidentialLocalConfig(residentialExitState{
		PrivateKey:    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		PeerPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		ListenPort:    51820,
	})
	if !strings.Contains(local, "Table = off") || !strings.Contains(local, "route replace default dev %i table 166 metric 100") {
		t.Fatalf("local WireGuard config does not use the guarded policy table: %s", local)
	}
}

func TestValidateResidentialRequestRejectsInjection(t *testing.T) {
	if _, err := validateResidentialRequest(model.ResidentialExitRequest{Endpoint: "a.example.com;reboot", ListenPort: 51820}); err == nil {
		t.Fatal("shell metacharacters in endpoint were accepted")
	}
	_, publicKey, err := wireGuardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = validateResidentialRequest(model.ResidentialExitRequest{Endpoint: "2001:db8::1", ListenPort: 51820, PeerPublicKey: publicKey}); err != nil {
		t.Fatalf("valid IPv6 endpoint and peer key were rejected: %v", err)
	}
}

func TestResidentialExitDemoWorkflowAndRemovalGuard(t *testing.T) {
	manager, _ := newDemoManager(t)
	first, err := manager.ConfigureResidentialExit(t.Context(), model.ResidentialExitRequest{
		Endpoint: "a.example.com", ListenPort: 51820,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Configured || first.PublicKey == "" || first.InstallScript == "" {
		t.Fatalf("first step did not return the peer bootstrap material: %#v", first)
	}
	_, peerPublicKey, err := wireGuardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	configured, err := manager.ConfigureResidentialExit(t.Context(), model.ResidentialExitRequest{
		Endpoint: "a.example.com", ListenPort: 51820, PeerPublicKey: peerPublicKey,
		ExpectedExitIP: "203.0.113.20",
	})
	if err != nil || !configured.Configured {
		t.Fatalf("second step did not configure the exit: %#v err=%v", configured, err)
	}
	node, err := manager.Create(t.Context(), model.NodeCreateRequest{
		Protocol: protocolHysteria2, Name: "Residential", Mode: "prefer_v6",
		Egress: "residential", Server: "node.example.com", Domain: "node.example.com",
		IPv4Bind: "192.0.2.5", IPv6Bind: "2001:db8::5", AutoBind: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.Egress != "residential" || node.Mode != "v4only" || node.AutoBind {
		t.Fatalf("created node did not preserve the residential policy: %#v", node)
	}
	if err = manager.RemoveResidentialExit(t.Context(), "REMOVE"); err == nil || !strings.Contains(err.Error(), node.Name) {
		t.Fatalf("exit removal was not blocked by its dependent node: %v", err)
	}
}
