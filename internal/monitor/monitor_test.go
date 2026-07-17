package monitor

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEndpointPacketUsesIPv4PacketLength(t *testing.T) {
	var pending int64
	if _, _, _, _, _, ok := endpointPacket("1700000000.1 IP (tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto UDP (17), length 1280)", &pending); ok {
		t.Fatal("metadata line must not produce a packet")
	}
	transport, port, host, clientPort, size, ok := endpointPacket("    192.0.2.10.45080 > 198.51.100.20.54321: UDP, length 1252", &pending)
	if !ok || transport != "udp" || port != 45080 || host != "198.51.100.20" || clientPort != "54321" || size != 1280 {
		t.Fatalf("unexpected IPv4 packet: %q %d %q %q %d %v", transport, port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketIncludesIPv6Header(t *testing.T) {
	var pending int64
	endpointPacket("1700000000.2 IP6 (flowlabel 0x1, hlim 64, next-header UDP (17) payload length: 1240)", &pending)
	transport, port, host, clientPort, size, ok := endpointPacket("    2001:db8::1.45081 > 2001:db8::2.54322: UDP, length 1232", &pending)
	if !ok || transport != "udp" || port != 45081 || host != "2001:db8::2" || clientPort != "54322" || size != 1280 {
		t.Fatalf("unexpected IPv6 packet: %q %d %q %q %d %v", transport, port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketRejectsLineWithoutLengthMetadata(t *testing.T) {
	var pending int64
	if _, _, _, _, _, ok := endpointPacket("192.0.2.10.45080 > 198.51.100.20.54321: UDP, length 100", &pending); ok {
		t.Fatal("endpoint without IP packet length metadata must be ignored")
	}
}

func TestEndpointPacketParsesAlpineSingleLineIPv6(t *testing.T) {
	var pending int64
	line := "1783909462.501781 eth0 Out IP6 (flowlabel 0x92a6f, hlim 64, next-header UDP (17) payload length: 1288) 2a01:db8::1.55119 > 2602:db8::2.56681: UDP, length 1280"
	transport, port, host, clientPort, size, ok := endpointPacket(line, &pending)
	if !ok || transport != "udp" || port != 55119 || host != "2602:db8::2" || clientPort != "56681" || size != 1328 {
		t.Fatalf("unexpected Alpine IPv6 packet: %q %d %q %q %d %v", transport, port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketParsesAlpineSingleLineIPv4(t *testing.T) {
	var pending int64
	line := "1783909462.501781 eth0 Out IP (tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto UDP (17), length 1280) 192.0.2.10.45115 > 198.51.100.20.56681: UDP, length 1252"
	transport, port, host, clientPort, size, ok := endpointPacket(line, &pending)
	if !ok || transport != "udp" || port != 45115 || host != "198.51.100.20" || clientPort != "56681" || size != 1280 {
		t.Fatalf("unexpected Alpine IPv4 packet: %q %d %q %q %d %v", transport, port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketCountsTCPPayloadAndSkipsACK(t *testing.T) {
	var pending int64
	endpointPacket("1700000000.3 IP (tos 0x0, ttl 64, id 2, offset 0, flags [DF], proto TCP (6), length 120)", &pending)
	transport, port, host, clientPort, size, ok := endpointPacket("    127.0.0.1.45116 > 127.0.0.1.53324: Flags [P.], seq 1:81, ack 1, win 512, length 80", &pending)
	if !ok || transport != "tcp" || port != 45116 || host != "127.0.0.1" || clientPort != "53324" || size != 80 {
		t.Fatalf("unexpected TCP payload packet: %q %d %q %q %d %v", transport, port, host, clientPort, size, ok)
	}

	endpointPacket("1700000000.4 IP (tos 0x0, ttl 64, id 3, offset 0, flags [DF], proto TCP (6), length 40)", &pending)
	if _, _, _, _, _, ok := endpointPacket("    127.0.0.1.45116 > 127.0.0.1.53324: Flags [.], ack 81, win 512, length 0", &pending); ok {
		t.Fatal("TCP ACK without payload must not count as device traffic")
	}
}

func TestEndpointPacketParsesLinuxAnySingleLineTCP(t *testing.T) {
	var pending int64
	line := "1783909462.501781 lo In IP (tos 0x0, ttl 64, id 4, offset 0, flags [DF], proto TCP (6), length 104) 127.0.0.1.45116 > 127.0.0.1.53324: Flags [P.], seq 1:65, ack 1, win 512, length 64"
	transport, port, host, clientPort, size, ok := endpointPacket(line, &pending)
	if !ok || transport != "tcp" || port != 45116 || host != "127.0.0.1" || clientPort != "53324" || size != 64 {
		t.Fatalf("unexpected Linux any TCP packet: %q %d %q %q %d %v", transport, port, host, clientPort, size, ok)
	}
}

func TestParseProcessStatHandlesNamesWithSpaces(t *testing.T) {
	name, ticks, ok := parseProcessStat("123 (worker process) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15")
	if !ok || name != "worker process" || ticks != 23 {
		t.Fatalf("unexpected process stat: %q %d %v", name, ticks, ok)
	}
}

func TestProcessStatusReadsNameAndRSS(t *testing.T) {
	name, rss := processStatus("Name:\tsing-box\nState:\tS\nVmRSS:\t  82256 kB\n")
	if name != "sing-box" || rss != 82_256*1024 {
		t.Fatalf("unexpected process status: %q %d", name, rss)
	}
}

func TestProcessDisplayNameOnlyClassifiesWukongSubcommands(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		want    string
	}{
		{"wukong-panel", "/usr/local/bin/wukong-panel\x00web\x00", "悟空 Web"},
		{"wukong-panel", "/usr/local/bin/wukong-panel\x00agent\x00", "悟空 Agent"},
		{"wukong-panel", "/usr/local/bin/wukong-panel\x00serve\x00", "悟空单体服务"},
		{"wukong-panel", "/usr/local/bin/wukong-panel\x00doctor\x00", "wukong-panel"},
		{"ld-musl-x86_64.", "ld-linux-x86-64.so.2\x00--argv0\x00/etc/s-box/sing-box\x00--preload\x00/lib/libgcompat.so.0\x00--\x00/etc/s-box/sing-box\x00run\x00-c\x00/etc/s-box/hy2-v6.json\x00", "sing-box"},
		{"ld-musl-x86_64.", "ld-linux-x86-64.so.2\x00--argv0\x00/usr/bin/other\x00", "ld-musl-x86_64."},
		{"python3", "python3\x00script.py\x00--token\x00secret\x00", "python3"},
	}
	for _, test := range tests {
		if got := processDisplayName(test.name, []byte(test.cmdline)); got != test.want {
			t.Fatalf("processDisplayName(%q) = %q, want %q", test.cmdline, got, test.want)
		}
	}
}

func TestProcessConfigPath(t *testing.T) {
	for _, cmdline := range []string{
		"/etc/s-box/sing-box\x00run\x00-c\x00/etc/s-box/device-group.json\x00",
		"/etc/s-box/sing-box\x00run\x00--config=/etc/s-box/device-group.json\x00",
	} {
		if got := processConfigPath([]byte(cmdline)); got != "/etc/s-box/device-group.json" {
			t.Fatalf("unexpected process config path %q", got)
		}
	}
}

func TestProcessSnapshotMapsSingBoxNodeNames(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}
	tempDir := t.TempDir()
	scriptPath := filepath.Join(tempDir, "hold.sh")
	if err := os.WriteFile(scriptPath, []byte("sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	singBoxPath := filepath.Join(tempDir, "sing-box")
	if err := os.Symlink("/bin/sh", singBoxPath); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(tempDir, "device-group.json")
	command := exec.Command(singBoxPath, scriptPath, "run", "--config="+configPath)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})

	collector := &Collector{lastProcessCPU: map[int]uint64{}}
	want := []string{"Apple-TV", "iPhone"}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		items, _ := collector.processSnapshot(1_000_000_000, map[string][]string{configPath: want})
		for _, item := range items {
			if item.PID != command.Process.Pid {
				continue
			}
			if len(item.Nodes) == len(want) && item.Nodes[0] == want[0] && item.Nodes[1] == want[1] {
				return
			}
			t.Fatalf("sing-box process node names missing: %#v", item)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sing-box helper process %d was not collected", command.Process.Pid)
}

func TestProcessSnapshotOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}
	collector := &Collector{lastProcessCPU: map[int]uint64{}}
	items, count := collector.processSnapshot(1_000_000_000, nil)
	if count == 0 || len(items) == 0 {
		t.Fatalf("empty Linux process snapshot: count=%d items=%d", count, len(items))
	}
	found := false
	for _, item := range items {
		if item.PID == os.Getpid() {
			found = item.Name != "" && item.RSSBytes > 0
			break
		}
	}
	if !found {
		t.Fatal("current process missing from Linux process snapshot")
	}
}

func TestEndpointProtocolTransports(t *testing.T) {
	tests := map[string]string{
		"hysteria2":       "udp",
		"tuic":            "udp",
		"shadowsocks":     "udp,tcp",
		"vless":           "tcp",
		"vless-ws-tunnel": "tcp",
		"trojan":          "tcp",
		"unknown":         "",
	}
	for protocol, want := range tests {
		if got := strings.Join(endpointTransports(protocol), ","); got != want {
			t.Fatalf("endpointTransports(%q) = %q, want %q", protocol, got, want)
		}
	}
}

func TestLiveTrafficUsesActualElapsedTimeAndHandlesCounterReset(t *testing.T) {
	collector := &Collector{}
	started := time.Unix(100, 0)
	collector.updateLive("eth0", 1_000, 2_000, started)
	collector.updateLive("eth0", 4_000, 8_000, started.Add(1500*time.Millisecond))
	sample := collector.LiveTraffic()
	if sample.Interface != "eth0" || sample.RXBPS != 2_000 || sample.TXBPS != 4_000 {
		t.Fatalf("unexpected live traffic sample: %#v", sample)
	}
	collector.updateLive("eth0", 100, 200, started.Add(2500*time.Millisecond))
	sample = collector.LiveTraffic()
	if sample.RXBPS != 0 || sample.TXBPS != 0 {
		t.Fatalf("counter reset produced a spike: %#v", sample)
	}
	collector.updateLive("eth1", 10_000, 20_000, started.Add(3500*time.Millisecond))
	sample = collector.LiveTraffic()
	if sample.Interface != "eth1" || sample.RXBPS != 0 || sample.TXBPS != 0 {
		t.Fatalf("interface change produced a spike: %#v", sample)
	}
}

func TestEndpointCaptureFilterSeparatesTCPAndUDPPorts(t *testing.T) {
	ports := map[string]map[int]struct{}{
		"udp": {45115: {}, 45080: {}},
		"tcp": {45116: {}, 45080: {}},
	}
	want := "(udp and (src port 45080 or src port 45115)) or (tcp and (src port 45080 or src port 45116))"
	if got := endpointCaptureFilter(ports); got != want {
		t.Fatalf("endpointCaptureFilter() = %q, want %q", got, want)
	}
}
