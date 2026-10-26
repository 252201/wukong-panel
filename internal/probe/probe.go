package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/252201/wukong-panel/internal/hostlocation"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/netcheck"
)

const Capability = "probe"

var Capabilities = []string{"overview", Capability, "probe.update"}

type Config struct {
	ControllerURL                string `json:"controllerUrl"`
	HostID                       string `json:"hostId"`
	HostName                     string `json:"hostName"`
	NetworkProbeTargets          string `json:"networkProbeTargets,omitempty"`
	NetworkProbeDomesticTargets  string `json:"networkProbeDomesticTargets,omitempty"`
}

type Client struct {
	Config       Config
	Token        string
	HTTP         *http.Client
	DownloadHTTP *http.Client
	Sampler      *Sampler
	Network      *netcheck.Service
	Location     *hostlocation.Detector
	Version      string
}

func controllerURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(value), "/") + "/")
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("controller must be a trusted HTTPS URL")
	}
	return parsed.String(), nil
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("controller endpoint must not redirect")
	}}
}

func newDownloadHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" && os.Getenv("WUKONG_TEST_PROBE_DOWNLOAD_URL") == "" {
				return errors.New("insecure redirect")
			}
			return nil
		},
	}
}

func (c *Client) getDownloadClient() *http.Client {
	if c.DownloadHTTP != nil {
		return c.DownloadHTTP
	}
	return newDownloadHTTPClient()
}

func identity(name string) model.FleetEnrollmentRequest {
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
	return model.FleetEnrollmentRequest{Name: name, Hostname: hostname, OS: osName, Arch: runtime.GOARCH, ServiceManager: manager, ProtocolVersion: model.FleetProtocolVersion, Capabilities: Capabilities}
}

func privateWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".probe-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

func Join(ctx context.Context, directory, controller, enrollmentToken, name string, client *http.Client) (Config, error) {
	endpoint, err := controllerURL(controller)
	if err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(enrollmentToken) == "" {
		return Config{}, errors.New("enrollment token required")
	}
	if client == nil {
		client = newHTTPClient()
	}
	requestBody := identity(name)
	requestBody.Token = enrollmentToken
	body, _ := json.Marshal(requestBody)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"api/v1/fleet/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return Config{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return Config{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Config{}, err
	}
	if response.StatusCode != http.StatusCreated {
		return Config{}, fmt.Errorf("enrollment failed: HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	var enrolled model.FleetEnrollmentResponse
	if err = json.Unmarshal(data, &enrolled); err != nil || enrolled.HostID == "" || enrolled.AgentToken == "" || enrolled.ProtocolVersion != model.FleetProtocolVersion {
		return Config{}, errors.New("invalid enrollment response")
	}
	config := Config{ControllerURL: endpoint, HostID: enrolled.HostID, HostName: requestBody.Name}
	encoded, _ := json.MarshalIndent(config, "", "  ")
	if err = privateWrite(filepath.Join(directory, "config.json"), append(encoded, '\n')); err != nil {
		return Config{}, err
	}
	if err = privateWrite(filepath.Join(directory, "token"), []byte(enrolled.AgentToken+"\n")); err != nil {
		return Config{}, err
	}
	return config, nil
}

func Load(directory string) (*Client, error) {
	raw, err := os.ReadFile(filepath.Join(directory, "config.json"))
	if err != nil {
		return nil, err
	}
	var config Config
	if err = json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	if config.ControllerURL, err = controllerURL(config.ControllerURL); err != nil {
		return nil, err
	}
	token, err := os.ReadFile(filepath.Join(directory, "token"))
	if err != nil {
		return nil, err
	}
	if config.HostID == "" || strings.TrimSpace(string(token)) == "" {
		return nil, errors.New("incomplete probe configuration")
	}
	targets := os.Getenv("WUKONG_NETWORK_PROBE_TARGETS")
	if targets == "" {
		targets = config.NetworkProbeTargets
	}
	domesticTargets := os.Getenv("WUKONG_NETWORK_PROBE_DOMESTIC_TARGETS")
	if domesticTargets == "" {
		domesticTargets = config.NetworkProbeDomesticTargets
	}
	return &Client{Config: config, Token: strings.TrimSpace(string(token)), HTTP: newHTTPClient(), Sampler: &Sampler{}, Network: netcheck.NewService(targets, domesticTargets, false, nil), Location: hostlocation.New()}, nil
}

func (c *Client) Heartbeat(ctx context.Context) error {
	now := c.Sampler.Sample()
	var serverHost string
	if loc := c.Location.Current(); loc != nil {
		serverHost = loc.PublicIP
	}
	if serverHost == "" {
		serverHost = c.Config.HostName
	}
	scannedNodes := ScanDirectories(serverHost)
	v4, v6 := hostlocation.GetInterfaceAddresses()
	snapshot := model.FleetSnapshot{
		Full:     true,
		Overview: model.Overview{Now: now, Network: c.Network.Current()},
		Location: c.Location.Current(),
		Nodes:    []model.Node{},
		ProbeNodes: scannedNodes,
		DeploymentDefaults: model.NodeDeploymentDefaults{
			IPv4: v4,
			IPv6: v6,
		},
	}
	heartbeat := model.FleetHeartbeat{ProtocolVersion: model.FleetProtocolVersion, PanelVersion: c.Version, Capabilities: Capabilities, Snapshot: snapshot}
	body, _ := json.Marshal(heartbeat)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Config.ControllerURL+"api/v1/fleet/agent/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("X-Wukong-Host-ID", c.Config.HostID)
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("heartbeat HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func (c *Client) Run(ctx context.Context) {
	go c.Network.Run(ctx)
	go c.Location.Run(ctx)
	go c.pollCommands(ctx)
	backoff := time.Second
	for ctx.Err() == nil {
		delay := 10 * time.Second
		if err := c.Heartbeat(ctx); err != nil && ctx.Err() == nil {
			log.Printf("probe heartbeat: %v", err)
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

func (c *Client) pollCommands(ctx context.Context) {
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Config.ControllerURL+"api/v1/fleet/agent/commands/next?wait=25", nil)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("X-Wukong-Host-ID", c.Config.HostID)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if resp.StatusCode == http.StatusNoContent {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		var command model.FleetCommand
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&command)
		resp.Body.Close()
		if err != nil {
			continue
		}
		if command.Kind == "probe.update" {
			c.handleProbeUpdate(ctx, command)
		}
	}
}

func (c *Client) sendCommandResult(ctx context.Context, id, status, resultErr string, resultData any) {
	var raw json.RawMessage
	if resultData != nil {
		b, _ := json.Marshal(resultData)
		raw = b
	}
	res := model.FleetCommandResult{
		Status: status,
		Result: raw,
		Error:  resultErr,
	}
	body, _ := json.Marshal(res)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Config.ControllerURL+"api/v1/fleet/agent/commands/"+url.PathEscape(id)+"/result", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Wukong-Host-ID", c.Config.HostID)
	resp, err := c.HTTP.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func (c *Client) handleProbeUpdate(ctx context.Context, command model.FleetCommand) {
	var req struct {
		TargetVersion string `json:"targetVersion"`
	}
	_ = json.Unmarshal(command.Payload, &req)
	cleanVer := strings.TrimPrefix(strings.TrimSpace(req.TargetVersion), "v")

	downloadClient := c.getDownloadClient()

	if cleanVer == "" || cleanVer == "latest" {
		ghReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/252201/wukong-panel/releases/latest", nil)
		if err == nil {
			ghReq.Header.Set("User-Agent", "wukong-probe/updater")
			ghReq.Header.Set("Accept", "application/vnd.github.v3+json")
			if ghResp, err := downloadClient.Do(ghReq); err == nil && ghResp.StatusCode == http.StatusOK {
				var payload struct {
					TagName string `json:"tag_name"`
				}
				if json.NewDecoder(ghResp.Body).Decode(&payload) == nil && payload.TagName != "" {
					cleanVer = strings.TrimPrefix(payload.TagName, "v")
				}
				ghResp.Body.Close()
			}
		}
	}

	if cleanVer == "" {
		c.sendCommandResult(ctx, command.ID, "failed", "无法确定目标版本", nil)
		return
	}

	arch := runtime.GOARCH
	assetName := fmt.Sprintf("wukong-probe-linux-%s", arch)
	baseURL := fmt.Sprintf("https://github.com/252201/wukong-panel/releases/download/v%s", cleanVer)
	if override := os.Getenv("WUKONG_TEST_PROBE_DOWNLOAD_URL"); override != "" {
		baseURL = override
	}

	// 1. Download SHA256SUMS
	sumsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/SHA256SUMS", nil)
	if err != nil {
		c.sendCommandResult(ctx, command.ID, "failed", err.Error(), nil)
		return
	}
	sumsReq.Header.Set("User-Agent", "wukong-probe/updater")
	sumsResp, err := downloadClient.Do(sumsReq)
	if err != nil || sumsResp.StatusCode != http.StatusOK {
		if sumsResp != nil && sumsResp.Body != nil {
			sumsResp.Body.Close()
		}
		errMsg := "下载校验清单失败"
		if err != nil {
			errMsg = fmt.Sprintf("下载校验清单失败: %v", err)
		} else if sumsResp != nil {
			errMsg = fmt.Sprintf("下载校验清单失败 (HTTP %d)", sumsResp.StatusCode)
		}
		c.sendCommandResult(ctx, command.ID, "failed", errMsg, nil)
		return
	}
	defer sumsResp.Body.Close()

	expectedSHA := ""
	scanner := bufio.NewScanner(io.LimitReader(sumsResp.Body, 1<<20))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && filepath.Base(fields[1]) == assetName {
			expectedSHA = strings.ToLower(fields[0])
			break
		}
	}
	if len(expectedSHA) != 64 {
		c.sendCommandResult(ctx, command.ID, "failed", "校验清单缺少有效哈希", nil)
		return
	}

	// 2. Download probe asset
	tmpFile, err := os.CreateTemp("", ".probe-stage-*")
	if err != nil {
		c.sendCommandResult(ctx, command.ID, "failed", err.Error(), nil)
		return
	}
	stagePath := tmpFile.Name()
	defer os.Remove(stagePath)

	binReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/"+assetName, nil)
	if err != nil {
		tmpFile.Close()
		c.sendCommandResult(ctx, command.ID, "failed", err.Error(), nil)
		return
	}
	binReq.Header.Set("User-Agent", "wukong-probe/updater")
	binResp, err := downloadClient.Do(binReq)
	if err != nil || binResp.StatusCode != http.StatusOK {
		tmpFile.Close()
		if binResp != nil && binResp.Body != nil {
			binResp.Body.Close()
		}
		errMsg := "下载探针二进制失败"
		if err != nil {
			errMsg = fmt.Sprintf("下载探针二进制失败: %v", err)
		} else if binResp != nil {
			errMsg = fmt.Sprintf("下载探针二进制失败 (HTTP %d)", binResp.StatusCode)
		}
		c.sendCommandResult(ctx, command.ID, "failed", errMsg, nil)
		return
	}
	defer binResp.Body.Close()

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmpFile, hasher), io.LimitReader(binResp.Body, 64<<20))
	if err != nil || written <= 0 {
		tmpFile.Close()
		c.sendCommandResult(ctx, command.ID, "failed", "保存探针文件失败", nil)
		return
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if actualSHA != expectedSHA {
		tmpFile.Close()
		c.sendCommandResult(ctx, command.ID, "failed", fmt.Sprintf("哈希不匹配 (期望: %s, 实际: %s)", expectedSHA, actualSHA), nil)
		return
	}

	_ = tmpFile.Chmod(0755)
	_ = tmpFile.Sync()
	_ = tmpFile.Close()

	// 3. Test execution
	testCmd := exec.CommandContext(ctx, stagePath, "version")
	if out, err := testCmd.CombinedOutput(); err != nil {
		c.sendCommandResult(ctx, command.ID, "failed", fmt.Sprintf("新版二进制测试执行失败: %s", strings.TrimSpace(string(out))), nil)
		return
	}

	// 4. Replace binary
	destBin := "/usr/local/bin/wukong-probe"
	if override := os.Getenv("WUKONG_TEST_PROBE_BIN"); override != "" {
		destBin = override
	} else if ex, err := os.Executable(); err == nil {
		if realEx, err := filepath.EvalSymlinks(ex); err == nil && filepath.Base(realEx) == "wukong-probe" {
			destBin = realEx
		}
	}

	if err := replaceExecutable(stagePath, destBin, 0755); err != nil {
		c.sendCommandResult(ctx, command.ID, "failed", fmt.Sprintf("替换目标二进制失败: %v", err), nil)
		return
	}

	c.sendCommandResult(ctx, command.ID, "success", "", map[string]any{"ok": true, "version": cleanVer})

	if os.Getenv("WUKONG_TEST_NO_EXIT") != "1" {
		go func() {
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}()
	}
}

func replaceExecutable(src, dst string, mode os.FileMode) error {
	if realDst, err := filepath.EvalSymlinks(dst); err == nil && realDst != "" {
		dst = realDst
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".new-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	tmpName = ""

	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}

	return nil
}

// Sample owns no database and observes only /proc and the root filesystem.
type Sampler struct {
	lastAt            time.Time
	lastCPU, lastIdle uint64
	lastRX, lastTX    int64
	lastInterface     string
}

func (s *Sampler) Sample() model.Metric {
	now := time.Now()
	iface := defaultInterface()
	rx, tx := networkBytes(iface)
	total, idle := readCPU()
	var cpu, rxRate, txRate float64
	if !s.lastAt.IsZero() {
		if total > s.lastCPU && idle >= s.lastIdle {
			cpu = (1 - float64(idle-s.lastIdle)/float64(total-s.lastCPU)) * 100
		}
		elapsed := now.Sub(s.lastAt).Seconds()
		if elapsed > 0 && iface == s.lastInterface {
			if rx >= s.lastRX {
				rxRate = float64(rx-s.lastRX) / elapsed
			}
			if tx >= s.lastTX {
				txRate = float64(tx-s.lastTX) / elapsed
			}
		}
	}
	s.lastAt, s.lastCPU, s.lastIdle, s.lastRX, s.lastTX, s.lastInterface = now, total, idle, rx, tx, iface
	if cpu < 0 {
		cpu = 0
	}
	if cpu > 100 {
		cpu = 100
	}
	memUsed, memTotal := memoryUsage()
	diskUsed, diskTotal := diskUsage()
	return model.Metric{Timestamp: now.Unix(), Interface: iface, RXBytes: rx, TXBytes: tx, RXBPS: rxRate, TXBPS: txRate, CPU: cpu, Memory: percent(memUsed, memTotal), MemoryUsedBytes: memUsed, MemoryTotalBytes: memTotal, Disk: percent(diskUsed, diskTotal), DiskUsedBytes: diskUsed, DiskTotalBytes: diskTotal, Load1: firstFloat("/proc/loadavg"), Uptime: int64(firstFloat("/proc/uptime"))}
}

func diskUsage() (int64, int64) {
	var stat syscall.Statfs_t
	if syscall.Statfs("/", &stat) != nil {
		return 0, 0
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	used := total - int64(stat.Bavail)*int64(stat.Bsize)
	if used < 0 {
		used = 0
	}
	return used, total
}

func percent(used, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}
