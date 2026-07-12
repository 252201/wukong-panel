package singboxconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ProbeResult struct {
	Config  string `json:"config"`
	Inbound string `json:"inbound"`
	Port    int    `json:"port"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

func ProbeDirectory(ctx context.Context, binary, configDir string) ([]ProbeResult, error) {
	files, err := filepath.Glob(filepath.Join(configDir, "*.json"))
	if err != nil {
		return nil, err
	}
	tempDir, err := os.MkdirTemp("", "wukong-hy2-probe-")
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
		for index, item := range inbounds {
			inbound, _ := item.(map[string]any)
			if stringValue(inbound["type"]) != "hysteria2" {
				continue
			}
			result := ProbeResult{Config: path, Inbound: stringValue(inbound["tag"]), Port: intNumber(inbound["listen_port"])}
			probe, buildErr := buildHY2Probe(inbound)
			if buildErr != nil {
				result.Error = buildErr.Error()
				results = append(results, result)
				continue
			}
			probePath := filepath.Join(tempDir, fmt.Sprintf("probe-%d.json", len(results)+index))
			if err = os.WriteFile(probePath, probe, 0o600); err != nil {
				return results, err
			}
			for _, target := range []string{"https://www.cloudflare.com/cdn-cgi/trace", "https://www.google.com/generate_204", "https://api64.ipify.org/"} {
				attemptCtx, cancel := context.WithTimeout(ctx, 18*time.Second)
				command := exec.CommandContext(attemptCtx, binary, "tools", "fetch", "-c", probePath, target)
				output, runErr := command.CombinedOutput()
				cancel()
				if runErr == nil {
					result.OK = true
					result.Error = ""
					break
				}
				message := strings.TrimSpace(string(output))
				if len(message) > 800 {
					message = message[len(message)-800:]
				}
				result.Error = fmt.Sprintf("HY2 probe via %s failed: %v: %s", target, runErr, message)
			}
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

func buildHY2Probe(inbound map[string]any) ([]byte, error) {
	port := intNumber(inbound["listen_port"])
	if port < 1 || port > 65535 {
		return nil, errorsText("invalid HY2 listen port")
	}
	password := ""
	if users, ok := inbound["users"].([]any); ok && len(users) > 0 {
		if user, ok := users[0].(map[string]any); ok {
			password = stringValue(user["password"])
		}
	}
	if password == "" {
		return nil, errorsText("HY2 inbound has no probeable user password")
	}
	server := stringValue(inbound["listen"])
	switch server {
	case "", "::", "::0", "[::]":
		server = "::1"
	case "0.0.0.0":
		server = "127.0.0.1"
	}
	outbound := map[string]any{"type": "hysteria2", "tag": "probe-out", "server": server, "server_port": port, "password": password, "tls": map[string]any{"enabled": true, "server_name": "localhost", "insecure": true, "alpn": []any{"h3"}}}
	root := map[string]any{"log": map[string]any{"level": "error"}, "outbounds": []any{outbound}, "route": map[string]any{"final": "probe-out"}}
	return json.MarshalIndent(root, "", "  ")
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
	return fmt.Errorf("%d of %d HY2 protocol probes failed", failed, len(results))
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
