package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

type Collector struct {
	store             *store.Store
	demo              bool
	lastCPU, lastIdle uint64
}

func New(s *store.Store, demo bool) *Collector { return &Collector{store: s, demo: demo} }

func (c *Collector) Run(ctx context.Context) {
	c.sample()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sample()
		}
	}
}

func (c *Collector) RunEndpoints(ctx context.Context) {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		c.sampleEndpoints(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

var endpointLine = regexp.MustCompile(`(?:IP6?|)\s+(.+?)\.(\d+) > (.+?)\.(\d+):.*length (\d+)`)

func (c *Collector) sampleEndpoints(parent context.Context) {
	settings, err := c.store.Settings()
	if err != nil || !settings.CollectEndpoints {
		return
	}
	nodes, err := c.store.Nodes(parent)
	if err != nil {
		return
	}
	byPort := map[int]model.Node{}
	filters := []string{}
	for _, node := range nodes {
		if node.Status != "active" {
			continue
		}
		byPort[node.ListenPort] = node
		filters = append(filters, fmt.Sprintf("src port %d", node.ListenPort))
	}
	if len(filters) == 0 {
		return
	}
	iface := settings.Interface
	if iface == "" || iface == "auto" {
		iface = defaultInterface()
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	args := []string{"-i", iface, "-nn", "-q", "-l", "-c", "500", "udp and (" + strings.Join(filters, " or ") + ")"}
	output, _ := exec.CommandContext(ctx, "tcpdump", args...).CombinedOutput()
	now := time.Now().Unix()
	for _, line := range strings.Split(string(output), "\n") {
		match := endpointLine.FindStringSubmatch(line)
		if len(match) != 6 {
			continue
		}
		sourcePort, _ := strconv.Atoi(match[2])
		node, ok := byPort[sourcePort]
		if !ok {
			continue
		}
		bytes, _ := strconv.ParseInt(match[5], 10, 64)
		host := strings.TrimSpace(match[3])
		port := match[4]
		endpoint := host + ":" + port
		if strings.Contains(host, ":") {
			endpoint = "[" + host + "]:" + port
		}
		_ = c.store.AddEndpointSample(now, node.ID, node.Name, endpoint, bytes)
	}
}

func (c *Collector) sample() {
	settings, _ := c.store.Settings()
	iface := settings.Interface
	if iface == "" || iface == "auto" {
		iface = defaultInterface()
	}
	rx, tx := networkBytes(iface)
	now := time.Now()
	oldIface, lastRX, lastTX, accRX, accTX, _ := c.store.TrafficState()
	deltaRX, deltaTX := int64(0), int64(0)
	if oldIface == iface {
		if rx >= lastRX {
			deltaRX = rx - lastRX
		}
		if tx >= lastTX {
			deltaTX = tx - lastTX
		}
		accRX += deltaRX
		accTX += deltaTX
	} else {
		lastRX = rx
		lastTX = tx
	}
	if c.demo && rx == 0 && tx == 0 {
		phase := float64(now.Unix()%120) / 120 * math.Pi * 2
		rx = accRX + int64(2_400_000+1_700_000*(1+math.Sin(phase)))
		tx = accTX + int64(1_100_000+700_000*(1+math.Cos(phase)))
		accRX += int64(4_000_000 + 2_000_000*(1+math.Sin(phase)))
		accTX += int64(1_800_000 + 900_000*(1+math.Cos(phase)))
		deltaRX = int64(4_000_000 + 2_000_000*(1+math.Sin(phase)))
		deltaTX = int64(1_800_000 + 900_000*(1+math.Cos(phase)))
	}
	elapsed := 10.0
	if last, err := c.store.Metrics(1); err == nil && len(last) == 1 {
		elapsed = math.Max(1, float64(now.Unix()-last[0].Timestamp))
	}
	m := model.Metric{Timestamp: now.Unix(), Interface: iface, RXBytes: accRX, TXBytes: accTX, RXBPS: float64(deltaRX) / elapsed, TXBPS: float64(deltaTX) / elapsed, CPU: c.cpuPercent(), Memory: memoryPercent(), Disk: diskPercent(), Load1: load1(), Uptime: uptime()}
	if c.demo {
		m.CPU = 18 + 8*math.Sin(float64(now.Unix())/17)
		m.Memory = 42.6
		m.Disk = 27.4
		m.Load1 = .38
	}
	_ = c.store.UpdateTrafficState(iface, rx, tx, accRX, accTX)
	location, err := time.LoadLocation(settings.Timezone)
	if err != nil {
		location = time.Local
	}
	_ = c.store.AddDailyTraffic(now.In(location).Format("2006-01-02"), deltaRX, deltaTX, "internal")
	_ = c.store.AddMetric(m)
}

func ImportVNStat(s *store.Store) error {
	path, err := exec.LookPath("vnstat")
	if err != nil {
		return nil
	}
	output, err := exec.Command(path, "--json", "d").Output()
	if err != nil {
		return err
	}
	var payload struct {
		Interfaces []struct {
			Traffic struct {
				Day []struct {
					Date struct {
						Year  int `json:"year"`
						Month int `json:"month"`
						Day   int `json:"day"`
					} `json:"date"`
					RX int64 `json:"rx"`
					TX int64 `json:"tx"`
				} `json:"day"`
			} `json:"traffic"`
		} `json:"interfaces"`
	}
	if err = json.Unmarshal(output, &payload); err != nil {
		return err
	}
	today := time.Now().Format("2006-01-02")
	for _, iface := range payload.Interfaces {
		for _, row := range iface.Traffic.Day {
			day := fmt.Sprintf("%04d-%02d-%02d", row.Date.Year, row.Date.Month, row.Date.Day)
			if day >= today {
				continue
			}
			_ = s.ImportDailyTraffic(day, row.RX, row.TX)
		}
	}
	return nil
}

func defaultInterface() string {
	if file, err := os.Open("/proc/net/route"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 2 && fields[1] == "00000000" && fields[0] != "Iface" {
				return fields[0]
			}
		}
	}
	ifaces, _ := net.Interfaces()
	for _, item := range ifaces {
		if item.Flags&net.FlagLoopback == 0 && item.Flags&net.FlagUp != 0 {
			return item.Name
		}
	}
	return "unknown"
}

func networkBytes(iface string) (int64, int64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != iface {
			continue
		}
		f := strings.Fields(parts[1])
		if len(f) >= 9 {
			rx, _ := strconv.ParseInt(f[0], 10, 64)
			tx, _ := strconv.ParseInt(f[8], 10, 64)
			return rx, tx
		}
	}
	return 0, 0
}

func readCPU() (uint64, uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	f := strings.Fields(line)
	var total uint64
	var idle uint64
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return total, idle
}
func (c *Collector) cpuPercent() float64 {
	total, idle := readCPU()
	if total == 0 {
		return 0
	}
	dt, di := total-c.lastCPU, idle-c.lastIdle
	c.lastCPU, c.lastIdle = total, idle
	if dt == 0 {
		return 0
	}
	value := (1 - float64(di)/float64(dt)) * 100
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
func memoryPercent() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return 0
	}
	values := map[string]float64{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			values[strings.TrimSuffix(f[0], ":")], _ = strconv.ParseFloat(f[1], 64)
		}
	}
	total := values["MemTotal"]
	if total == 0 {
		return 0
	}
	return (total - values["MemAvailable"]) / total * 100
}
func diskPercent() float64 {
	var stat syscall.Statfs_t
	if syscall.Statfs("/", &stat) != nil {
		return 0
	}
	total := float64(stat.Blocks) * float64(stat.Bsize)
	free := float64(stat.Bavail) * float64(stat.Bsize)
	if total == 0 {
		return 0
	}
	return (total - free) / total * 100
}
func load1() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}
func uptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return int64(v)
}
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (c *Collector) Diagnostic() string { return fmt.Sprintf("iface=%s", defaultInterface()) }
