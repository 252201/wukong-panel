package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/252201/wukong-panel/internal/agent"
	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/monitor"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/singboxconfig"
	"github.com/252201/wukong-panel/internal/store"
	webserver "github.com/252201/wukong-panel/internal/web"
)

var version = "dev"

type directAgent struct{ manager *agent.Manager }

func (d directAgent) Health(ctx context.Context) (map[string]any, error) {
	return map[string]any{"ok": true, "version": d.manager.Version(ctx)}, nil
}
func (d directAgent) Scan(ctx context.Context) ([]model.NodeCandidate, error) {
	return d.manager.Scan(ctx)
}
func (d directAgent) DeploymentDefaults(ctx context.Context) (model.NodeDeploymentDefaults, error) {
	return d.manager.DeploymentDefaults(ctx)
}
func (d directAgent) Import(ctx context.Context, ids []string) error {
	_, err := d.manager.Import(ctx, ids)
	return err
}
func (d directAgent) DeleteCandidate(ctx context.Context, id string, r model.CandidateDeleteRequest) error {
	return d.manager.DeleteCandidate(ctx, id, r.ConfirmName)
}
func (d directAgent) Create(ctx context.Context, r model.NodeCreateRequest) (model.Node, error) {
	return d.manager.Create(ctx, r)
}
func (d directAgent) CreateBatch(ctx context.Context, r model.NodeBatchCreateRequest) ([]model.Node, error) {
	return d.manager.CreateBatch(ctx, r)
}
func (d directAgent) EditDetails(ctx context.Context, id string) (model.NodeEditDetails, error) {
	return d.manager.EditDetails(ctx, id)
}
func (d directAgent) Edit(ctx context.Context, id string, r model.NodeEditRequest) error {
	return d.manager.Edit(ctx, id, r)
}
func (d directAgent) Action(ctx context.Context, id string, r model.NodeActionRequest) error {
	return d.manager.Action(ctx, id, r.Action, r.ConfirmName)
}
func (d directAgent) Rename(ctx context.Context, id string, r model.NodeRenameRequest) error {
	return d.manager.Rename(ctx, id, r)
}
func (d directAgent) Share(ctx context.Context, id string) (model.Share, error) {
	return d.manager.Share(ctx, id)
}
func (d directAgent) MigrationPlan(ctx context.Context, target string) (singboxconfig.Plan, error) {
	return d.manager.MigrationPlan(ctx, target)
}

func main() {
	cfg := config.Parse(version)
	if cfg.Command == "singbox" {
		runSingBoxCLI(context.Background(), cfg, cfg.Args)
		return
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	if cfg.Command == "reset-password" && os.Geteuid() != 0 {
		log.Fatal("reset-password must be run as root")
	}
	if cfg.Command != "reset-password" && cfg.AgentToken == "" {
		token, err := ensureToken(cfg.AgentTokenFile)
		if err != nil {
			log.Fatal(err)
		}
		cfg.AgentToken = token
	}
	s, err := store.Open(filepath.Join(cfg.DataDir, "wukong.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cfg.Command {
	case "reset-password":
		password, err := s.ResetAdminPassword()
		fatalIf(err)
		fmt.Printf("WUKONG_RESET_PASSWORD=%s\n", password)
		fmt.Println("The admin must change this temporary password after signing in. All existing sessions were revoked.")
		return
	case "init":
		vault := mustVault(cfg.SecretDir)
		password, created, err := s.EnsureAdmin()
		fatalIf(err)
		if created {
			fmt.Printf("WUKONG_INITIAL_PASSWORD=%s\n", password)
		}
		if subscription, _ := s.Setting("subscription_token"); subscription == "" {
			value, _ := security.RandomToken(24)
			_ = s.SetSetting("subscription_token", value)
		}
		_ = vault
		fmt.Printf("data_dir=%s\nbase_path=%s\n", cfg.DataDir, cfg.BasePath)
		return
	case "doctor":
		manager := agent.NewManager(cfg, s, nil)
		runDoctor(ctx, cfg, s, manager)
		return
	case "scan":
		manager := agent.NewManager(cfg, s, nil)
		items, err := manager.Scan(ctx)
		fatalIf(err)
		_ = json.NewEncoder(os.Stdout).Encode(items)
		return
	case "node":
		manager := agent.NewManager(cfg, s, mustVault(cfg.SecretDir))
		runNodeCLI(ctx, manager, cfg.Args)
		return
	case "agent":
		manager := agent.NewManager(cfg, s, mustVault(cfg.DataDir))
		_ = monitor.ImportVNStat(s)
		collector := monitor.New(s, cfg.Demo)
		go collector.Run(ctx)
		go collector.RunEndpoints(ctx)
		go manager.RunReconciler(ctx)
		server := agent.NewServer(manager, cfg.AgentToken)
		fatalServe(server.ListenAndServe(ctx, cfg.AgentSocket))
		return
	case "web":
		client := agent.NewClient(cfg.AgentSocket, cfg.AgentToken)
		server := webserver.New(cfg, s, client, version)
		fatalServe(server.ListenAndServe(ctx))
		return
	case "serve":
		vault := mustVault(cfg.SecretDir)
		password, created, err := s.EnsureAdmin()
		fatalIf(err)
		if created {
			fmt.Printf("WUKONG_INITIAL_PASSWORD=%s\n", password)
		}
		if subscription, _ := s.Setting("subscription_token"); subscription == "" {
			value, _ := security.RandomToken(24)
			_ = s.SetSetting("subscription_token", value)
		}
		if cfg.Demo {
			fatalIf(s.SeedDemo(vault))
		}
		manager := agent.NewManager(cfg, s, vault)
		_ = monitor.ImportVNStat(s)
		collector := monitor.New(s, cfg.Demo)
		go collector.Run(ctx)
		go collector.RunEndpoints(ctx)
		go manager.RunReconciler(ctx)
		go func() { <-ctx.Done() }()
		server := webserver.New(cfg, s, directAgent{manager}, version)
		fatalServe(server.ListenAndServe(ctx))
		return
	default:
		log.Fatalf("unknown command %q (use serve, agent, web, init, reset-password, doctor, scan, node, singbox)", cfg.Command)
	}
}

func runSingBoxCLI(ctx context.Context, cfg config.Config, args []string) {
	if len(args) == 0 {
		log.Fatal("usage: wukong-panel singbox plan|migrate|check-interfaces|probe [options]")
	}
	flags := flag.NewFlagSet("singbox "+args[0], flag.ExitOnError)
	target := flags.String("target", "1.13.14", "target sing-box version")
	configDir := flags.String("config-dir", cfg.ConfigDir, "source configuration directory")
	outputDir := flags.String("output-dir", "", "migration output directory")
	binary := flags.String("binary", cfg.SingBoxBin, "sing-box binary used for protocol probing")
	server := flags.String("server", "", "override HY2 server address for an external-path probe")
	serverName := flags.String("server-name", "", "TLS server name for an external-path probe")
	jsonOutput := flags.Bool("json", false, "print JSON result")
	if err := flags.Parse(args[1:]); err != nil {
		log.Fatal(err)
	}
	var plan singboxconfig.Plan
	var err error
	switch args[0] {
	case "plan":
		plan, err = singboxconfig.PlanDirectory(*configDir, *target)
	case "migrate":
		if *outputDir == "" {
			log.Fatal("--output-dir is required")
		}
		plan, err = singboxconfig.MigrateDirectory(*configDir, *outputDir, *target)
	case "check-interfaces":
		plan, err = singboxconfig.PlanDirectory(*configDir, *target)
		if err == nil {
			for _, file := range plan.Files {
				for _, name := range file.Interfaces {
					if _, interfaceErr := net.InterfaceByName(name); interfaceErr != nil {
						err = fmt.Errorf("configuration %s references unavailable network interface %s", file.Path, name)
						break
					}
				}
			}
		}
	case "probe":
		probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		results, probeErr := singboxconfig.ProbeDirectory(probeCtx, *binary, *configDir, *server, *serverName)
		if *jsonOutput {
			_ = json.NewEncoder(os.Stdout).Encode(results)
		} else {
			for _, result := range results {
				status := "OK"
				if !result.OK {
					status = "FAILED"
				}
				fmt.Printf("%s %s %s:%d %s\n", status, result.Protocol, filepath.Base(result.Config), result.Port, result.Error)
			}
		}
		if probeErr != nil {
			log.Fatal(probeErr)
		}
		return
	default:
		log.Fatalf("unknown singbox subcommand %q", args[0])
	}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(plan)
	} else {
		printMigrationPlan(plan)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func printMigrationPlan(plan singboxconfig.Plan) {
	fmt.Printf("sing-box target: %s\ncompatible: %t\nchanges: %d\nwarnings: %d\nerrors: %d\n", plan.Target, plan.Compatible, plan.Changes, plan.Warnings, plan.Errors)
	for _, file := range plan.Files {
		fmt.Printf("\n%s\n", file.Path)
		for _, change := range file.Changes {
			fmt.Printf("  + %s\n", change)
		}
		for _, warning := range file.Warnings {
			fmt.Printf("  ! %s\n", warning)
		}
		for _, problem := range file.Errors {
			fmt.Printf("  x %s\n", problem)
		}
	}
}

func runNodeCLI(ctx context.Context, manager *agent.Manager, args []string) {
	if len(args) == 0 {
		log.Fatal("usage: wukongctl node create|action [options]")
	}
	switch args[0] {
	case "create":
		flags := flag.NewFlagSet("node create", flag.ExitOnError)
		var request model.NodeCreateRequest
		var domains, deviceNames, instance, publicIPv4, tunnelTokenFile string
		flags.StringVar(&request.Name, "name", "Wukong-Node", "node display name")
		flags.StringVar(&request.Protocol, "protocol", "hysteria2", "hysteria2, vless, vless-ws-tunnel, shadowsocks, tuic or trojan")
		flags.StringVar(&request.Mode, "mode", "prefer_v6", "prefer_v6, v4only or v6only")
		flags.IntVar(&request.ListenPort, "port", 0, "listen port, zero selects a free protocol-compatible port")
		flags.StringVar(&request.Server, "server", "", "advertised server domain or IP")
		flags.StringVar(&publicIPv4, "ipv4", "", "compatibility advertised IPv4")
		flags.StringVar(&request.Domain, "domain", "", "TLS server name or VLESS REALITY handshake server")
		flags.StringVar(&request.WebSocketPath, "ws-path", "", "VLESS WebSocket path; empty generates a random path")
		flags.StringVar(&tunnelTokenFile, "tunnel-token-file", "", "file containing a Cloudflare Tunnel token")
		flags.StringVar(&request.IPv4Bind, "ipv4-bind", "", "local IPv4 bind address")
		flags.StringVar(&request.IPv6Bind, "ipv6", "", "local IPv6 bind address")
		flags.StringVar(&request.Password, "password", "", "explicit password or VLESS UUID")
		flags.StringVar(&request.CertificatePath, "certificate", "", "existing certificate path")
		flags.StringVar(&request.KeyPath, "key", "", "existing private key path")
		flags.StringVar(&domains, "v6only-domains", "chatgpt.com,claude.ai,anthropic.com", "comma-separated IPv6-only domains")
		flags.StringVar(&deviceNames, "device-nodes", "", "comma-separated device node names")
		flags.StringVar(&instance, "instance", "", "compatibility instance label")
		_ = flags.Bool("yes", false, "skip confirmation")
		deviceStartPort := flags.Int("device-start-port", 0, "first device port; zero selects random ports")
		_ = flags.String("acme-method", "", "managed by panel certificate settings")
		_ = flags.String("acme-ip-version", "", "managed by panel certificate settings")
		_ = flags.String("acme-server", "", "managed by panel certificate settings")
		_ = flags.String("dns-provider", "", "managed by panel certificate settings")
		_ = flags.String("email", "", "managed by panel certificate settings")
		_ = flags.Bool("skip-http-precheck", false, "compatibility flag")
		if err := flags.Parse(args[1:]); err != nil {
			log.Fatal(err)
		}
		if tunnelTokenFile != "" {
			data, err := os.ReadFile(tunnelTokenFile)
			if err != nil {
				log.Fatalf("read Cloudflare Tunnel token file: %v", err)
			}
			request.TunnelToken = strings.TrimSpace(string(data))
		}
		if agentProtocol := strings.ToLower(strings.TrimSpace(request.Protocol)); (agentProtocol == "vless-ws-tunnel" || agentProtocol == "vless-ws" || agentProtocol == "cloudflare-tunnel" || agentProtocol == "argo") && strings.TrimSpace(deviceNames) != "" {
			log.Fatal("Tunnel device batches require one distinct Cloudflare hostname per device; create the batch from the panel")
		}
		request.AutoBind = true
		for _, domain := range strings.Split(domains, ",") {
			if value := strings.TrimSpace(domain); value != "" {
				request.V6OnlyDomains = append(request.V6OnlyDomains, value)
			}
		}
		if request.Server == "" && publicIPv4 != "" {
			request.Server = publicIPv4
		}
		if request.Server == "" {
			request.Server = request.Domain
		}
		if instance != "" && request.Name == "Wukong-HY2" {
			request.Name = "Wukong-" + instance
		}
		created := []model.Node{}
		node, err := manager.Create(ctx, request)
		fatalIf(err)
		created = append(created, node)
		deviceIndex := 0
		for _, name := range strings.Split(deviceNames, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			device := request
			device.Name = name
			device.ListenPort = 0
			if *deviceStartPort > 0 {
				device.ListenPort = *deviceStartPort + deviceIndex
			}
			device.Password = ""
			node, err = manager.Create(ctx, device)
			fatalIf(err)
			created = append(created, node)
			deviceIndex++
		}
		_ = json.NewEncoder(os.Stdout).Encode(created)
	case "action":
		flags := flag.NewFlagSet("node action", flag.ExitOnError)
		id := flags.String("id", "", "node ID")
		action := flags.String("action", "", "start, stop, restart, check, probe or delete")
		confirm := flags.String("confirm-name", "", "required for delete")
		_ = flags.Parse(args[1:])
		if *id == "" || *action == "" {
			log.Fatal("--id and --action are required")
		}
		fatalIf(manager.Action(ctx, *id, *action, *confirm))
		fmt.Println("ok")
	default:
		log.Fatalf("unknown node subcommand %q", args[0])
	}
}

func mustVault(dataDir string) *security.Vault {
	vault, err := security.OpenVault(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	return vault
}

func ensureToken(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	if data, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	token, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}
func runDoctor(ctx context.Context, cfg config.Config, s *store.Store, manager *agent.Manager) {
	nodes, _ := s.Nodes(ctx)
	metrics, _ := s.Metrics(1)
	result := map[string]any{"ok": true, "version": version, "singBoxVersion": manager.Version(ctx), "dataDir": cfg.DataDir, "configDir": cfg.ConfigDir, "nodeCount": len(nodes), "hasMetrics": len(metrics) > 0, "serviceManager": serviceManager()}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
func serviceManager() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	return "unknown"
}
func fatalIf(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func fatalServe(err error) {
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
