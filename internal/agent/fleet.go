package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/store"
)

var FleetCapabilities = []string{
	"overview", "nodes.read", "nodes.write", "imports", "share", "settings",
	"residential-exit", "socks-exit", "sing-box-migration", "subscription-render",
}

type FleetClientConfig struct {
	ControllerURL string `json:"controllerUrl"`
	HostID        string `json:"hostId"`
	HostName      string `json:"hostName"`
}

type FleetConnector struct {
	cfg        config.Config
	client     FleetClientConfig
	token      string
	store      *store.Store
	manager    *Manager
	version    string
	http       *http.Client
	mutate     sync.Mutex
	heartbeats atomic.Uint64
}

func LoadFleetClientConfig(cfg config.Config) (FleetClientConfig, string, error) {
	data, err := os.ReadFile(cfg.FleetConfigFile)
	if err != nil {
		return FleetClientConfig{}, "", err
	}
	var client FleetClientConfig
	if err = json.Unmarshal(data, &client); err != nil {
		return FleetClientConfig{}, "", err
	}
	token, err := os.ReadFile(cfg.FleetTokenFile)
	if err != nil {
		return FleetClientConfig{}, "", err
	}
	client.ControllerURL = strings.TrimRight(strings.TrimSpace(client.ControllerURL), "/") + "/"
	if parsed, parseErr := url.Parse(client.ControllerURL); parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return FleetClientConfig{}, "", errors.New("fleet controller URL must use trusted HTTPS")
	}
	if client.HostID == "" || strings.TrimSpace(string(token)) == "" {
		return FleetClientConfig{}, "", errors.New("incomplete fleet client configuration")
	}
	return client, strings.TrimSpace(string(token)), nil
}

func NewFleetConnector(cfg config.Config, s *store.Store, manager *Manager, version string) (*FleetConnector, error) {
	client, token, err := LoadFleetClientConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &FleetConnector{cfg: cfg, client: client, token: token, store: s, manager: manager, version: version, http: NewTrustedFleetHTTPClient(40 * time.Second)}, nil
}

func NewTrustedFleetHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if request.URL.Scheme != "https" {
				return errors.New("fleet controller redirect must keep trusted HTTPS")
			}
			return nil
		},
	}
}

func (c *FleetConnector) Run(ctx context.Context) {
	go c.heartbeatLoop(ctx)
	c.commandLoop(ctx)
}

func (c *FleetConnector) heartbeatLoop(ctx context.Context) {
	backoff := time.Second
	for {
		delay := 10 * time.Second
		if err := c.sendHeartbeat(ctx); err != nil && ctx.Err() == nil {
			log.Printf("fleet heartbeat: %v", err)
			delay = backoff + time.Duration(rand.IntN(750))*time.Millisecond
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			backoff = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *FleetConnector) commandLoop(ctx context.Context) {
	delay := time.Second
	for ctx.Err() == nil {
		command, found, err := c.nextCommand(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("fleet command poll: %v", err)
			wait := delay + time.Duration(rand.IntN(750))*time.Millisecond
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			if delay < 30*time.Second {
				delay *= 2
			}
			continue
		}
		delay = time.Second
		if !found {
			continue
		}
		result := c.execute(ctx, command)
		if err = c.sendResult(ctx, command.ID, result); err != nil {
			log.Printf("fleet command result %s: %v", command.ID, err)
		}
	}
}

func (c *FleetConnector) endpoint(path string) string {
	return c.client.ControllerURL + "api/v1/fleet/agent/" + path
}

func (c *FleetConnector) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Wukong-Host-ID", c.client.HostID)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func (c *FleetConnector) sendHeartbeat(ctx context.Context) error {
	count := c.heartbeats.Add(1)
	snapshot, err := c.snapshot(ctx, count == 1 || count%6 == 0)
	if err != nil {
		return err
	}
	request := model.FleetHeartbeat{ProtocolVersion: model.FleetProtocolVersion, PanelVersion: c.version, SingBoxVersion: c.manager.Version(ctx), Capabilities: FleetCapabilities, Snapshot: snapshot}
	response, err := c.request(ctx, http.MethodPost, "heartbeat", request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func (c *FleetConnector) nextCommand(ctx context.Context) (model.FleetCommand, bool, error) {
	response, err := c.request(ctx, http.MethodGet, "commands/next?wait=25", nil)
	if err != nil {
		return model.FleetCommand{}, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return model.FleetCommand{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return model.FleetCommand{}, false, fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	var command model.FleetCommand
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&command); err != nil {
		return command, false, err
	}
	return command, true, nil
}

func (c *FleetConnector) sendResult(ctx context.Context, id string, result model.FleetCommandResult) error {
	response, err := c.request(ctx, http.MethodPost, "commands/"+url.PathEscape(id)+"/result", result)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return nil
}

func (c *FleetConnector) snapshot(ctx context.Context, full bool) (model.FleetSnapshot, error) {
	nodes, err := c.store.Nodes(ctx)
	if err != nil {
		return model.FleetSnapshot{}, err
	}
	metrics, _ := c.store.Metrics(1)
	devices, _ := c.store.ActiveDevices(25*time.Second, 12)
	processes, count, _ := c.store.Processes(20)
	settings, _ := c.store.Settings()
	billingStart, billingEnd := fleetBillingPeriod(time.Now(), settings.BillingResetDay, settings.Timezone)
	usedRX, usedTX, _ := c.store.TrafficBetween(billingStart.Format("2006-01-02"), billingEnd.Format("2006-01-02"))
	var now model.Metric
	if len(metrics) > 0 {
		now = metrics[len(metrics)-1]
	}
	details := make(map[string]model.NodeEditDetails, len(nodes))
	online := 0
	for _, node := range nodes {
		if node.Status == "active" {
			online++
		}
		if full && node.Ownership == "managed" {
			if value, e := c.manager.EditDetails(ctx, node.ID); e == nil {
				details[node.ID] = value
			}
		}
	}
	snapshot := model.FleetSnapshot{Full: full, Overview: model.Overview{Now: now, Devices: devices, Processes: processes, ProcessCount: count, NodeCount: len(nodes), OnlineNodes: online, TrafficUsed: usedRX + usedTX, TrafficQuota: settings.TrafficQuotaBytes, BillingStart: billingStart.Format("2006-01-02"), BillingEnd: billingEnd.Format("2006-01-02"), SingBoxVersion: c.manager.Version(ctx), PanelVersion: c.version}, Nodes: nodes}
	if !full {
		for index := range snapshot.Nodes {
			node := snapshot.Nodes[index]
			snapshot.Nodes[index] = model.Node{ID: node.ID, Name: node.Name, Status: node.Status, ProbeStatus: node.ProbeStatus, ProbeLatencyMS: node.ProbeLatencyMS, ProbeExitIP: node.ProbeExitIP, ProbeError: node.ProbeError, ProbeCheckedAt: node.ProbeCheckedAt}
		}
		return snapshot, nil
	}
	jobs, _ := c.store.Jobs(30)
	settings.SubscriptionToken = ""
	defaults, _ := c.manager.DeploymentDefaults(ctx)
	residential, _ := c.manager.ResidentialExit(ctx)
	residential.InstallScript = ""
	socks, _ := c.manager.SOCKSExit(ctx)
	endpoints, _ := c.store.TopEndpoints(10)
	for index := range endpoints {
		endpoints[index].Endpoint = maskFleetEndpoint(endpoints[index].Endpoint)
	}
	timeline, _ := fleetTrafficTimeline(c.store, time.Now(), settings)
	snapshot.NodeDetails = details
	snapshot.Jobs = jobs
	snapshot.Settings = settings
	snapshot.DeploymentDefaults = defaults
	snapshot.ResidentialExit = &residential
	snapshot.SOCKSExit = &socks
	snapshot.Endpoints = endpoints
	snapshot.Timeline = timeline
	return snapshot, nil
}

func maskFleetEndpoint(value string) string {
	if value == "cloudflare-tunnel" {
		return "Cloudflare Tunnel"
	}
	if strings.HasPrefix(value, "[") {
		if index := strings.LastIndex(value, "]:"); index >= 0 {
			return "[****:****]" + value[index+1:]
		}
		return "[****:****]"
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "***"
	}
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		return parts[0] + ".***.***." + parts[3] + ":" + port
	}
	return "***:" + port
}

func fleetBillingPeriod(now time.Time, day int, timezone string) (time.Time, time.Time) {
	if day < 1 || day > 28 {
		day = 1
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		location = time.Local
	}
	local := now.In(location)
	year, month := local.Year(), local.Month()
	if local.Day() < day {
		month--
		if month == 0 {
			month = 12
			year--
		}
	}
	start := time.Date(year, month, day, 0, 0, 0, 0, location)
	return start, start.AddDate(0, 1, 0).Add(-time.Second)
}

func fleetTrafficTimeline(s *store.Store, now time.Time, settings model.Settings) (model.TrafficTimeline, error) {
	location, err := time.LoadLocation(settings.Timezone)
	if err != nil {
		location = time.Local
	}
	localNow := now.In(location)
	todayStart := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, location)
	result := model.TrafficTimeline{Today: make([]model.TrafficBucket, 24), Timezone: location.String()}
	for hour := range 24 {
		started := todayStart.Add(time.Duration(hour) * time.Hour)
		result.Today[hour] = model.TrafficBucket{Label: fmt.Sprintf("%02d", hour), StartedAt: started.Unix()}
	}
	metrics, err := s.MetricsBetween(todayStart.Add(-time.Minute).Unix(), now.Unix())
	if err != nil {
		return result, err
	}
	for index := 1; index < len(metrics); index++ {
		current, previous := metrics[index], metrics[index-1]
		if current.Timestamp < todayStart.Unix() {
			continue
		}
		hour := time.Unix(current.Timestamp, 0).In(location).Hour()
		rx := current.RXBytes - previous.RXBytes
		tx := current.TXBytes - previous.TXBytes
		if rx > 0 {
			result.Today[hour].RXBytes += rx
			result.TodayRX += rx
		}
		if tx > 0 {
			result.Today[hour].TXBytes += tx
			result.TodayTX += tx
		}
	}
	start, end := fleetBillingPeriod(now, settings.BillingResetDay, settings.Timezone)
	result.BillingStart = start.Format("2006-01-02")
	result.BillingEnd = end.Format("2006-01-02")
	buckets, err := s.TrafficBuckets(result.BillingStart, result.BillingEnd)
	if err != nil {
		return result, err
	}
	result.Billing = buckets
	for _, item := range buckets {
		result.BillingRX += item.RXBytes
		result.BillingTX += item.TXBytes
	}
	return result, nil
}

type fleetSubscriptionEntry struct {
	Node  model.Node  `json:"node"`
	Share model.Share `json:"share"`
}

func (c *FleetConnector) execute(ctx context.Context, command model.FleetCommand) model.FleetCommandResult {
	if receipt, err := c.store.FleetReceipt(command.ID); err == nil {
		return receipt
	}
	if time.Now().After(command.ExpiresAt) {
		return model.FleetCommandResult{Status: "failed", Error: "命令已过期"}
	}
	c.mutate.Lock()
	defer c.mutate.Unlock()
	timeout := time.Until(command.ExpiresAt)
	if timeout <= 0 {
		return model.FleetCommandResult{Status: "failed", Error: "命令已过期"}
	}
	localJob, _ := c.store.CreateJob("fleet."+command.Kind, command.ID)
	if localJob.ID != "" {
		_ = c.store.UpdateJob(localJob.ID, "running", 20, "中央命令执行中", "")
	}
	if timeout > 2*time.Minute {
		timeout = 2 * time.Minute
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := c.executeOnce(execCtx, command)
	status := "success"
	if err != nil {
		status = "failed"
	}
	raw, _ := json.Marshal(result)
	commandResult := model.FleetCommandResult{Status: status, Result: raw}
	if err != nil {
		commandResult.Error = err.Error()
		commandResult.Result = nil
	}
	if localJob.ID != "" {
		if err != nil {
			_ = c.store.UpdateJob(localJob.ID, "failed", 100, "中央命令执行失败", err.Error())
		} else {
			_ = c.store.UpdateJob(localJob.ID, "success", 100, "中央命令执行完成", "")
		}
	}
	_ = c.store.SaveFleetReceipt(command.ID, commandResult.Status, string(commandResult.Result), commandResult.Error)
	actor := command.Actor
	if actor == "" {
		actor = "fleet-controller"
	}
	_ = c.store.Audit(actor, "fleet.command."+command.Kind, c.client.HostID, command.ID+" "+status)
	return commandResult
}

func (c *FleetConnector) executeOnce(ctx context.Context, command model.FleetCommand) (any, error) {
	switch command.Kind {
	case "imports.scan":
		items, err := c.manager.Scan(ctx)
		for i := range items {
			items[i].Secret = ""
		}
		return items, err
	case "imports.confirm":
		var r struct {
			Fingerprints []string `json:"fingerprints"`
		}
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		count, err := c.manager.Import(ctx, r.Fingerprints)
		return map[string]int{"imported": count}, err
	case "candidate.delete":
		var r struct {
			ID      string                       `json:"id"`
			Request model.CandidateDeleteRequest `json:"request"`
		}
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return nil, c.manager.DeleteCandidate(ctx, r.ID, r.Request.ConfirmName)
	case "node.create":
		var r model.NodeCreateRequest
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return c.manager.Create(ctx, r)
	case "node.create_batch":
		var r model.NodeBatchCreateRequest
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return c.manager.CreateBatch(ctx, r)
	case "node.edit":
		var r struct {
			ID      string                `json:"id"`
			Request model.NodeEditRequest `json:"request"`
		}
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return nil, c.manager.Edit(ctx, r.ID, r.Request)
	case "node.rename":
		var r struct {
			ID      string                  `json:"id"`
			Request model.NodeRenameRequest `json:"request"`
		}
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return nil, c.manager.Rename(ctx, r.ID, r.Request)
	case "node.action":
		var r struct {
			ID      string                  `json:"id"`
			Request model.NodeActionRequest `json:"request"`
		}
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return nil, c.manager.Action(ctx, r.ID, r.Request.Action, r.Request.ConfirmName)
	case "node.share":
		var r struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return c.manager.Share(ctx, r.ID)
	case "migration.plan":
		var r struct {
			Target string `json:"target"`
		}
		_ = json.Unmarshal(command.Payload, &r)
		return c.manager.MigrationPlan(ctx, r.Target)
	case "residential.configure":
		var r model.ResidentialExitRequest
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return c.manager.ConfigureResidentialExit(ctx, r)
	case "residential.remove":
		var r model.ResidentialExitDeleteRequest
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return nil, c.manager.RemoveResidentialExit(ctx, r.Confirm)
	case "socks.configure":
		var r model.SOCKSExitRequest
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return c.manager.ConfigureSOCKSExit(ctx, r)
	case "socks.remove":
		var r model.SOCKSExitDeleteRequest
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return nil, c.manager.RemoveSOCKSExit(ctx, r.Confirm)
	case "settings.save":
		var r model.Settings
		if err := json.Unmarshal(command.Payload, &r); err != nil {
			return nil, err
		}
		return nil, c.store.SaveSettings(r)
	case "settings.rotate-subscription":
		token, err := security.RandomToken(24)
		if err == nil {
			err = c.store.SetSetting("subscription_token", token)
		}
		return map[string]string{"token": token}, err
	case "subscription.render":
		nodes, err := c.store.Nodes(ctx)
		if err != nil {
			return nil, err
		}
		entries := []fleetSubscriptionEntry{}
		for _, node := range nodes {
			if node.Status != "active" {
				continue
			}
			share, e := c.manager.Share(ctx, node.ID)
			if e == nil {
				entries = append(entries, fleetSubscriptionEntry{Node: node, Share: share})
			}
		}
		return entries, nil
	default:
		return nil, fmt.Errorf("unsupported fleet command %q", command.Kind)
	}
}

func RuntimeFleetIdentity(name, version string) model.FleetHost {
	hostname, _ := os.Hostname()
	if strings.TrimSpace(name) == "" {
		name = hostname
	}
	osName := "linux"
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ID=") {
				osName = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
				break
			}
		}
	}
	manager := "unknown"
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		manager = "systemd"
	} else if _, err = os.Stat("/sbin/openrc-run"); err == nil {
		manager = "openrc"
	}
	return model.FleetHost{Name: name, Hostname: hostname, OS: osName, Arch: runtime.GOARCH, ServiceManager: manager, PanelVersion: version, ProtocolVersion: model.FleetProtocolVersion, Capabilities: FleetCapabilities}
}
