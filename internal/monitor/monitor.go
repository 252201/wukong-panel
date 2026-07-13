package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
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
	lastProcessTotal  uint64
	lastProcessCPU    map[int]uint64
}

func New(s *store.Store, demo bool) *Collector {
	return &Collector{store: s, demo: demo, lastProcessCPU: map[int]uint64{}}
}

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

var (
	endpointLine = regexp.MustCompile(`(?:^|\s)([^\s]+)\.(\d+) > ([^\s]+)\.(\d+):`)
	ipv4Length   = regexp.MustCompile(`proto UDP \(\d+\), length (\d+)\)`)
	ipv6Payload  = regexp.MustCompile(`payload length: (\d+)`)
)

func endpointPacket(line string, pendingBytes *int64) (sourcePort int, host, port string, packetBytes int64, ok bool) {
	if strings.Contains(line, " IP6 ") {
		if match := ipv6Payload.FindStringSubmatch(line); len(match) == 2 {
			payload, _ := strconv.ParseInt(match[1], 10, 64)
			*pendingBytes = payload + 40
		}
	}
	if strings.Contains(line, " IP ") {
		if match := ipv4Length.FindStringSubmatch(line); len(match) == 2 {
			*pendingBytes, _ = strconv.ParseInt(match[1], 10, 64)
		}
	}
	match := endpointLine.FindStringSubmatch(line)
	if len(match) != 5 || *pendingBytes <= 0 {
		return 0, "", "", 0, false
	}
	sourcePort, _ = strconv.Atoi(match[2])
	host, port, packetBytes = strings.TrimSpace(match[3]), match[4], *pendingBytes
	*pendingBytes = 0
	return sourcePort, host, port, packetBytes, true
}

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
		if node.Status != "active" || !udpEndpointProtocol(node.Protocol) {
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
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	args := []string{"-i", iface, "-nn", "-tt", "-v", "-l", "udp and (" + strings.Join(filters, " or ") + ")"}
	command := exec.CommandContext(ctx, "tcpdump", args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return
	}
	command.Stderr = io.Discard
	startedAt := time.Now()
	if err = command.Start(); err != nil {
		return
	}
	samples := map[string]store.EndpointWindowSample{}
	var pendingBytes int64
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		sourcePort, host, port, packetBytes, ok := endpointPacket(scanner.Text(), &pendingBytes)
		if !ok {
			continue
		}
		node, ok := byPort[sourcePort]
		if !ok {
			continue
		}
		endpoint := host + ":" + port
		if strings.Contains(host, ":") {
			endpoint = "[" + host + "]:" + port
		}
		key := node.ID + "\x00" + endpoint
		sample := samples[key]
		sample.NodeID = node.ID
		sample.NodeName = node.Name
		sample.Endpoint = endpoint
		sample.Bytes += packetBytes
		samples[key] = sample
	}
	_ = command.Wait()
	duration := time.Since(startedAt)
	if parent.Err() != nil || duration < time.Second {
		return
	}
	now := time.Now().Unix()
	window := make([]store.EndpointWindowSample, 0, len(samples))
	for _, sample := range samples {
		window = append(window, sample)
	}
	_ = c.store.ReplaceEndpointWindow(now, duration, window)
}

func udpEndpointProtocol(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "hysteria2", "tuic", "shadowsocks":
		return true
	default:
		return false
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
	memoryUsed, memoryTotal, memoryValue := memoryUsage()
	diskUsed, diskTotal, diskValue := diskUsage()
	if c.demo {
		memoryTotal = 2_000_000_000
		memoryUsed = 852_000_000
		memoryValue = 42.6
		diskTotal = 40_000_000_000
		diskUsed = 10_960_000_000
		diskValue = 27.4
	}
	processes, processCount := c.processSnapshot(memoryTotal)
	if c.demo && len(processes) == 0 {
		processes = []model.ProcessStat{
			{PID: 1421, Name: "sing-box", CPU: 6.9, RSSBytes: 84_230_000, MemoryPercent: 4.2},
			{PID: os.Getpid(), Name: "wukong-panel", CPU: 4.1, RSSBytes: 40_190_000, MemoryPercent: 2.0},
			{PID: 852, Name: "python3", CPU: 1.6, RSSBytes: 11_960_000, MemoryPercent: .6},
			{PID: 872, Name: "tcpdump", CPU: .4, RSSBytes: 6_760_000, MemoryPercent: .3},
		}
		processCount = 106
	}
	m := model.Metric{Timestamp: now.Unix(), Interface: iface, RXBytes: accRX, TXBytes: accTX, RXBPS: float64(deltaRX) / elapsed, TXBPS: float64(deltaTX) / elapsed, CPU: c.cpuPercent(), Memory: memoryValue, MemoryUsedBytes: memoryUsed, MemoryTotalBytes: memoryTotal, Disk: diskValue, DiskUsedBytes: diskUsed, DiskTotalBytes: diskTotal, Load1: load1(), Uptime: uptime()}
	if c.demo {
		m.CPU = 18 + 8*math.Sin(float64(now.Unix())/17)
		m.Load1 = .38
	}
	_ = c.store.UpdateTrafficState(iface, rx, tx, accRX, accTX)
	location, err := time.LoadLocation(settings.Timezone)
	if err != nil {
		location = time.Local
	}
	_ = c.store.AddDailyTraffic(now.In(location).Format("2006-01-02"), deltaRX, deltaTX, "internal")
	_ = c.store.AddMetric(m)
	_ = c.store.ReplaceProcesses(now.Unix(), processCount, processes)
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
func memoryUsage() (used, total int64, percent float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return 0, 0, 0
	}
	values := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			value, _ := strconv.ParseInt(f[1], 10, 64)
			values[strings.TrimSuffix(f[0], ":")] = value * 1024
		}
	}
	total = values["MemTotal"]
	if total == 0 {
		return 0, 0, 0
	}
	used = max64(0, total-values["MemAvailable"])
	return used, total, float64(used) / float64(total) * 100
}
func diskUsage() (used, total int64, percent float64) {
	var stat syscall.Statfs_t
	if syscall.Statfs("/", &stat) != nil {
		return 0, 0, 0
	}
	total = int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bavail) * int64(stat.Bsize)
	if total == 0 {
		return 0, 0, 0
	}
	used = max64(0, total-free)
	return used, total, float64(used) / float64(total) * 100
}

func parseProcessStat(data string) (string, uint64, bool) {
	start, end := strings.Index(data, "("), strings.LastIndex(data, ")")
	if start < 0 || end <= start {
		return "", 0, false
	}
	fields := strings.Fields(data[end+1:])
	if len(fields) < 13 {
		return "", 0, false
	}
	userTicks, errUser := strconv.ParseUint(fields[11], 10, 64)
	systemTicks, errSystem := strconv.ParseUint(fields[12], 10, 64)
	if errUser != nil || errSystem != nil {
		return "", 0, false
	}
	return data[start+1 : end], userTicks + systemTicks, true
}

func processStatus(data string) (string, int64) {
	name := ""
	rss := int64(0)
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "Name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		}
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.ParseInt(fields[1], 10, 64)
				rss = value * 1024
			}
		}
	}
	return name, rss
}

func processDisplayName(name string, cmdline []byte) string {
	fields := strings.FieldsFunc(string(cmdline), func(r rune) bool { return r == 0 })
	if strings.HasPrefix(name, "ld-musl-") {
		for _, field := range fields {
			if filepath.Base(field) == "sing-box" {
				return "sing-box"
			}
		}
		return name
	}
	if name != "wukong-panel" || len(fields) < 2 || filepath.Base(fields[0]) != "wukong-panel" {
		return name
	}
	switch fields[1] {
	case "web":
		return "悟空 Web"
	case "agent":
		return "悟空 Agent"
	case "serve":
		return "悟空单体服务"
	default:
		return name
	}
}

func (c *Collector) processSnapshot(memoryTotal int64) ([]model.ProcessStat, int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0
	}
	totalCPU, _ := readCPU()
	totalDelta := uint64(0)
	if totalCPU >= c.lastProcessTotal {
		totalDelta = totalCPU - c.lastProcessTotal
	}
	current := map[int]uint64{}
	items := []model.ProcessStat{}
	totalCount := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		statData, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		name, ticks, ok := parseProcessStat(string(statData))
		if !ok {
			continue
		}
		totalCount++
		statusData, _ := os.ReadFile("/proc/" + entry.Name() + "/status")
		statusName, rss := processStatus(string(statusData))
		if statusName != "" {
			name = statusName
		}
		if name == "wukong-panel" || strings.HasPrefix(name, "ld-musl-") {
			cmdline, _ := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
			name = processDisplayName(name, cmdline)
		}
		cpu := 0.0
		if previous, exists := c.lastProcessCPU[pid]; exists && ticks >= previous && totalDelta > 0 {
			cpu = float64(ticks-previous) / float64(totalDelta) * float64(max(1, runtime.NumCPU())) * 100
		}
		memoryPercent := 0.0
		if memoryTotal > 0 {
			memoryPercent = float64(rss) / float64(memoryTotal) * 100
		}
		current[pid] = ticks
		items = append(items, model.ProcessStat{PID: pid, Name: name, CPU: cpu, RSSBytes: rss, MemoryPercent: memoryPercent})
	}
	c.lastProcessCPU = current
	c.lastProcessTotal = totalCPU
	sort.Slice(items, func(i, j int) bool {
		if items[i].CPU == items[j].CPU {
			return items[i].RSSBytes > items[j].RSSBytes
		}
		return items[i].CPU > items[j].CPU
	})
	if len(items) > 100 {
		items = items[:100]
	}
	return items, totalCount
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
