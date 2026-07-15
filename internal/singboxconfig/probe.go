package singboxconfig

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ProbeResult struct {
	Config    string `json:"config"`
	Inbound   string `json:"inbound"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	LatencyMS int64  `json:"latencyMs,omitempty"`
	Target    string `json:"target,omitempty"`
	ExitIP    string `json:"exitIp,omitempty"`
}

var probeableProtocols = map[string]bool{
	"hysteria2":   true,
	"vless":       true,
	"shadowsocks": true,
	"tuic":        true,
	"trojan":      true,
}

func ProbeDirectory(ctx context.Context, binary, configDir, serverOverride, serverName string) ([]ProbeResult, error) {
	files, err := filepath.Glob(filepath.Join(configDir, "*.json"))
	if err != nil {
		return nil, err
	}
	tempDir, err := os.MkdirTemp("", "wukong-protocol-probe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)
	results := []ProbeResult{}
	for _, path := range files {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return results, readErr
		}
		var root map[string]any
		if err = json.Unmarshal(data, &root); err != nil {
			return results, err
		}
		inbounds, _ := root["inbounds"].([]any)
		for _, item := range inbounds {
			inbound, _ := item.(map[string]any)
			protocol := strings.ToLower(stringValue(inbound["type"]))
			if !probeableProtocols[protocol] {
				continue
			}
			result := ProbeResult{Config: path, Inbound: stringValue(inbound["tag"]), Protocol: protocol, Port: intNumber(inbound["listen_port"])}
			probe, buildErr := buildProtocolProbe(inbound, serverOverride, serverName)
			if buildErr != nil {
				result.Error = buildErr.Error()
				results = append(results, result)
				continue
			}
			result = executeProtocolProbe(ctx, binary, filepath.Join(tempDir, fmt.Sprintf("probe-%d.json", len(results))), probe, result)
			results = append(results, result)
		}
	}
	for _, result := range results {
		if !result.OK {
			return results, errorsForProbe(results)
		}
	}
	return results, nil
}

// ProbeConfigInbound performs a full local client round trip through one inbound.
// It validates authentication, TLS/REALITY negotiation and the node's outbound
// internet access without exposing credentials outside the root-only process.
func ProbeConfigInbound(ctx context.Context, binary, configPath, protocol string, port int) (ProbeResult, error) {
	result := ProbeResult{Config: configPath, Protocol: strings.ToLower(strings.TrimSpace(protocol)), Port: port}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return result, err
	}
	var root map[string]any
	if err = json.Unmarshal(data, &root); err != nil {
		return result, err
	}
	inbounds, _ := root["inbounds"].([]any)
	var selected map[string]any
	for _, item := range inbounds {
		inbound, _ := item.(map[string]any)
		inboundProtocol := strings.ToLower(stringValue(inbound["type"]))
		protocolMatches := result.Protocol == "" || inboundProtocol == result.Protocol
		if result.Protocol == "vless-ws-tunnel" && inboundProtocol == "vless" {
			transport, _ := inbound["transport"].(map[string]any)
			protocolMatches = stringValue(transport["type"]) == "ws"
		}
		if intNumber(inbound["listen_port"]) == port && protocolMatches {
			selected = inbound
			if result.Protocol == "" {
				result.Protocol = inboundProtocol
			}
			result.Inbound = stringValue(inbound["tag"])
			break
		}
	}
	if selected == nil {
		return result, fmt.Errorf("%s inbound on port %d was not found", result.Protocol, port)
	}
	if !probeableProtocols[result.Protocol] && result.Protocol != "vless-ws-tunnel" {
		return result, fmt.Errorf("unsupported probe protocol %q", result.Protocol)
	}
	probe, err := buildProtocolProbe(selected, "", "")
	if err != nil {
		return result, err
	}
	tempDir, err := os.MkdirTemp("", "wukong-node-probe-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(tempDir)
	result = executeProtocolProbe(ctx, binary, filepath.Join(tempDir, "probe.json"), probe, result)
	if !result.OK {
		return result, errorsText(result.Error)
	}
	return result, nil
}

func executeProtocolProbe(ctx context.Context, binary, probePath string, probe []byte, result ProbeResult) ProbeResult {
	if err := os.WriteFile(probePath, probe, 0o600); err != nil {
		result.Error = err.Error()
		return result
	}
	for _, target := range []string{"https://www.cloudflare.com/cdn-cgi/trace", "https://www.google.com/generate_204", "https://api64.ipify.org/"} {
		started := time.Now()
		attemptCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		command := exec.CommandContext(attemptCtx, binary, "tools", "fetch", "-c", probePath, target)
		output, runErr := command.CombinedOutput()
		cancel()
		result.LatencyMS = max(int64(1), time.Since(started).Milliseconds())
		result.Target = probeTargetName(target)
		if runErr == nil {
			result.OK = true
			result.Error = ""
			result.ExitIP = extractProbeIP(string(output))
			return result
		}
		message := strings.TrimSpace(string(output))
		if len(message) > 800 {
			message = message[len(message)-800:]
		}
		result.Error = fmt.Sprintf("%s probe via %s failed: %v: %s", result.Protocol, result.Target, runErr, message)
	}
	return result
}

func probeTargetName(value string) string {
	parsed, err := url.Parse(value)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return value
}

func extractProbeIP(output string) string {
	for _, line := range strings.Split(output, "\n") {
		value := strings.TrimSpace(line)
		if strings.HasPrefix(value, "ip=") {
			value = strings.TrimSpace(strings.TrimPrefix(value, "ip="))
		}
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func buildProtocolProbe(inbound map[string]any, serverOverride, serverName string) ([]byte, error) {
	protocol := strings.ToLower(stringValue(inbound["type"]))
	if protocol == "" {
		protocol = "hysteria2"
	}
	port := intNumber(inbound["listen_port"])
	if port < 1 || port > 65535 {
		return nil, errorsText("invalid " + protocol + " listen port")
	}
	server, insecure := probeServer(inbound, serverOverride)
	outbound := map[string]any{"type": protocol, "tag": "probe-out", "server": server, "server_port": port}
	firstUser := func() map[string]any {
		users, _ := inbound["users"].([]any)
		if len(users) == 0 {
			return nil
		}
		user, _ := users[0].(map[string]any)
		return user
	}
	switch protocol {
	case "hysteria2":
		password := stringValue(firstUser()["password"])
		if password == "" {
			return nil, errorsText("Hysteria2 inbound has no probeable user password")
		}
		outbound["password"] = password
		outbound["tls"] = probeTLS(server, serverName, insecure, true)
	case "vless":
		user := firstUser()
		uuid := stringValue(user["uuid"])
		if uuid == "" {
			return nil, errorsText("VLESS inbound has no probeable user UUID")
		}
		outbound["uuid"] = uuid
		if flow := stringValue(user["flow"]); flow != "" {
			outbound["flow"] = flow
		}
		transport, _ := inbound["transport"].(map[string]any)
		if stringValue(transport["type"]) == "ws" {
			outbound["transport"] = transport
			break
		}
		tlsInbound, _ := inbound["tls"].(map[string]any)
		realityInbound, _ := tlsInbound["reality"].(map[string]any)
		privateKey := stringValue(realityInbound["private_key"])
		publicKey := realityPublicKey(privateKey)
		shortID := firstString(realityInbound["short_id"])
		if publicKey == "" || shortID == "" {
			return nil, errorsText("VLESS REALITY inbound has incomplete key material")
		}
		handshake, _ := realityInbound["handshake"].(map[string]any)
		if serverName == "" {
			serverName = stringValue(handshake["server"])
		}
		outbound["tls"] = map[string]any{
			"enabled": true, "server_name": serverName,
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": publicKey, "short_id": shortID},
		}
	case "shadowsocks":
		method, password := stringValue(inbound["method"]), stringValue(inbound["password"])
		if method == "" || password == "" {
			return nil, errorsText("Shadowsocks inbound has no probeable method/password")
		}
		outbound["method"], outbound["password"] = method, password
	case "tuic":
		user := firstUser()
		uuid, password := stringValue(user["uuid"]), stringValue(user["password"])
		if uuid == "" || password == "" {
			return nil, errorsText("TUIC inbound has no probeable UUID/password")
		}
		outbound["uuid"], outbound["password"] = uuid, password
		outbound["congestion_control"] = "bbr"
		outbound["udp_relay_mode"] = "native"
		outbound["tls"] = probeTLS(server, serverName, insecure, true)
	case "trojan":
		password := stringValue(firstUser()["password"])
		if password == "" {
			return nil, errorsText("Trojan inbound has no probeable user password")
		}
		outbound["password"] = password
		outbound["tls"] = probeTLS(server, serverName, insecure, false)
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	root := map[string]any{"log": map[string]any{"level": "error"}, "outbounds": []any{outbound}, "route": map[string]any{"final": "probe-out"}}
	return json.MarshalIndent(root, "", "  ")
}

// ProbeVLESSWebSocketEndpoint validates the complete public Cloudflare path,
// including edge TLS, WebSocket upgrade, VLESS authentication and proxy egress.
func ProbeVLESSWebSocketEndpoint(ctx context.Context, binary, dialServer, publishedServer, uuid, path string) (ProbeResult, error) {
	dialServer = strings.TrimSpace(dialServer)
	publishedServer = strings.TrimSpace(publishedServer)
	if dialServer == "" {
		dialServer = publishedServer
	}
	result := ProbeResult{Protocol: "vless-ws-tunnel", Inbound: publishedServer, Port: 443}
	probe, err := buildVLESSWebSocketEndpointProbe(dialServer, publishedServer, uuid, path)
	if err != nil {
		return result, err
	}
	tempDir, err := os.MkdirTemp("", "wukong-tunnel-probe-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(tempDir)
	result.Config = filepath.Join(tempDir, "probe.json")
	result = executeProtocolProbe(ctx, binary, result.Config, probe, result)
	if !result.OK {
		return result, errorsText(result.Error)
	}
	return result, nil
}

func buildVLESSWebSocketEndpointProbe(dialServer, publishedServer, uuid, path string) ([]byte, error) {
	dialServer = strings.TrimSpace(dialServer)
	publishedServer = strings.TrimSpace(publishedServer)
	if dialServer == "" {
		dialServer = publishedServer
	}
	uuid = strings.TrimSpace(uuid)
	path = strings.TrimSpace(path)
	if dialServer == "" || publishedServer == "" || uuid == "" || !strings.HasPrefix(path, "/") {
		return nil, errorsText("VLESS WebSocket endpoint parameters are incomplete")
	}
	outbound := map[string]any{
		"type":        "vless",
		"tag":         "probe-out",
		"server":      dialServer,
		"server_port": 443,
		"uuid":        uuid,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": publishedServer,
			"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
		},
		"transport": map[string]any{
			"type":    "ws",
			"path":    path,
			"headers": map[string]any{"Host": publishedServer},
		},
	}
	root := map[string]any{"log": map[string]any{"level": "error"}, "outbounds": []any{outbound}, "route": map[string]any{"final": "probe-out"}}
	return json.MarshalIndent(root, "", "  ")
}

func buildHY2Probe(inbound map[string]any, serverOverride, serverName string) ([]byte, error) {
	if stringValue(inbound["type"]) == "" {
		inbound["type"] = "hysteria2"
	}
	return buildProtocolProbe(inbound, serverOverride, serverName)
}

func probeServer(inbound map[string]any, override string) (string, bool) {
	if override != "" {
		return override, false
	}
	server := stringValue(inbound["listen"])
	switch server {
	case "", "::", "::0", "[::]":
		server = "::1"
	case "0.0.0.0":
		server = "127.0.0.1"
	}
	return server, true
}

func probeTLS(server, serverName string, insecure, h3 bool) map[string]any {
	if serverName == "" {
		serverName = server
	}
	tlsConfig := map[string]any{"enabled": true, "server_name": serverName, "insecure": insecure}
	if h3 {
		tlsConfig["alpn"] = []any{"h3"}
	}
	return tlsConfig
}

func realityPublicKey(privateValue string) string {
	privateBytes, err := base64.RawURLEncoding.DecodeString(privateValue)
	if err != nil {
		return ""
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
}

func firstString(value any) string {
	values, _ := value.([]any)
	if len(values) == 0 {
		return ""
	}
	return stringValue(values[0])
}

type errorsText string

func (e errorsText) Error() string { return string(e) }

func errorsForProbe(results []ProbeResult) error {
	failed := 0
	for _, result := range results {
		if !result.OK {
			failed++
		}
	}
	return fmt.Errorf("%d of %d protocol probes failed", failed, len(results))
}

func intNumber(value any) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	default:
		return 0
	}
}
