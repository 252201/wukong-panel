package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
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

var Capabilities = []string{"overview", Capability}

type Config struct {
	ControllerURL string `json:"controllerUrl"`
	HostID        string `json:"hostId"`
	HostName      string `json:"hostName"`
}

type Client struct {
	Config   Config
	Token    string
	HTTP     *http.Client
	Sampler  *Sampler
	Network  *netcheck.Service
	Location *hostlocation.Detector
	Version  string
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
	return &Client{Config: config, Token: strings.TrimSpace(string(token)), HTTP: newHTTPClient(), Sampler: &Sampler{}, Network: netcheck.NewService("", "", false, nil), Location: hostlocation.New()}, nil
}

func (c *Client) Heartbeat(ctx context.Context) error {
	now := c.Sampler.Sample()
	snapshot := model.FleetSnapshot{Full: true, Overview: model.Overview{Now: now, Network: c.Network.Current()}, Location: c.Location.Current(), Nodes: []model.Node{}}
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
