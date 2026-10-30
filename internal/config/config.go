package config

import (
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Command                     string
	Listen                      string
	AgentSocket                 string
	AgentToken                  string
	AgentTokenFile              string
	DataDir                     string
	SecretDir                   string
	ConfigDir                   string
	SingBoxBin                  string
	CloudflaredBin              string
	TLSCertFile                 string
	TLSKeyFile                  string
	PanelDomain                 string
	BasePath                    string
	SecureCookie                bool
	Demo                        bool
	FleetConfigFile             string
	FleetTokenFile              string
	NetworkProbeTargets         string
	NetworkProbeDomesticTargets string
	Args                        []string
}

func Parse(version string) Config {
	originalArgs := append([]string(nil), os.Args...)
	command := "serve"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		command = os.Args[1]
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}
	isCtl := len(originalArgs) > 0 && filepath.Base(originalArgs[0]) == "wukongctl"
	if isCtl && (len(originalArgs) <= 1 || originalArgs[1] == "--help" || originalArgs[1] == "-h" || originalArgs[1] == "help") {
		command = "help"
	}
	dataDir := env("WUKONG_DATA_DIR", "/var/lib/wukong-panel")
	cfg := Config{Command: command}
	if len(originalArgs) > 2 {
		cfg.Args = originalArgs[2:]
	}
	if command == "node" || command == "singbox" || command == "fleet" || command == "update" || command == "help" {
		os.Args = []string{os.Args[0]}
	}
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.StringVar(&cfg.Listen, "listen", env("WUKONG_LISTEN", "127.0.0.1:8788"), "web listen address")
	flags.StringVar(&cfg.AgentSocket, "agent-socket", env("WUKONG_AGENT_SOCKET", "/run/wukong-panel/agent.sock"), "agent unix socket")
	flags.StringVar(&cfg.AgentToken, "agent-token", env("WUKONG_AGENT_TOKEN", ""), "agent authentication token")
	flags.StringVar(&cfg.AgentTokenFile, "agent-token-file", env("WUKONG_AGENT_TOKEN_FILE", ""), "agent token file")
	flags.StringVar(&cfg.DataDir, "data-dir", dataDir, "data directory")
	flags.StringVar(&cfg.SecretDir, "secret-dir", env("WUKONG_SECRET_DIR", ""), "root-only secret directory")
	flags.StringVar(&cfg.ConfigDir, "config-dir", env("WUKONG_SINGBOX_CONFIG_DIR", "/etc/s-box"), "sing-box config directory")
	flags.StringVar(&cfg.SingBoxBin, "sing-box", env("WUKONG_SINGBOX_BIN", "/etc/s-box/sing-box"), "sing-box binary")
	flags.StringVar(&cfg.CloudflaredBin, "cloudflared", env("WUKONG_CLOUDFLARED_BIN", "/usr/local/bin/cloudflared"), "cloudflared binary")
	flags.StringVar(&cfg.TLSCertFile, "tls-cert", env("WUKONG_TLS_CERT", "/etc/wukong-panel/tls/fullchain.cer"), "trusted panel certificate available to managed nodes")
	flags.StringVar(&cfg.TLSKeyFile, "tls-key", env("WUKONG_TLS_KEY", "/etc/wukong-panel/tls/private.key"), "private key for the trusted panel certificate")
	flags.StringVar(&cfg.PanelDomain, "panel-domain", env("WUKONG_PANEL_DOMAIN", ""), "public panel domain used as the default node endpoint")
	flags.StringVar(&cfg.BasePath, "base-path", env("WUKONG_BASE_PATH", "/wukong/"), "public base path")
	flags.BoolVar(&cfg.SecureCookie, "secure-cookie", envBool("WUKONG_SECURE_COOKIE", true), "set secure cookies")
	flags.BoolVar(&cfg.Demo, "demo", envBool("WUKONG_DEMO", false), "seed demo data")
	flags.StringVar(&cfg.FleetConfigFile, "fleet-config-file", env("WUKONG_FLEET_CONFIG_FILE", "/etc/wukong-panel/fleet.json"), "fleet satellite configuration file")
	flags.StringVar(&cfg.FleetTokenFile, "fleet-token-file", env("WUKONG_FLEET_TOKEN_FILE", "/etc/wukong-panel/fleet.token"), "fleet satellite token file")
	flags.StringVar(&cfg.NetworkProbeTargets, "network-probe-targets", env("WUKONG_NETWORK_PROBE_TARGETS", "1.1.1.1,8.8.8.8"), "comma-separated IPv4 addresses for local ICMP network checks")
	flags.StringVar(&cfg.NetworkProbeDomesticTargets, "network-probe-domestic-targets", env("WUKONG_NETWORK_PROBE_DOMESTIC_TARGETS", "194.138.202.35|223.5.5.5,138.113.151.1"), "comma-separated IPv4 addresses for domestic ICMP checks")
	_ = flags.Parse(os.Args[1:])
	if cfg.AgentTokenFile == "" {
		cfg.AgentTokenFile = filepath.Join(cfg.DataDir, "agent.token")
	}
	if cfg.SecretDir == "" {
		cfg.SecretDir = filepath.Join(cfg.DataDir, "secrets")
	}
	if !strings.HasPrefix(cfg.BasePath, "/") {
		cfg.BasePath = "/" + cfg.BasePath
	}
	if !strings.HasSuffix(cfg.BasePath, "/") {
		cfg.BasePath += "/"
	}
	if cfg.AgentToken == "" {
		if b, err := os.ReadFile(cfg.AgentTokenFile); err == nil {
			cfg.AgentToken = strings.TrimSpace(string(b))
		}
	}
	_ = version
	return cfg
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
