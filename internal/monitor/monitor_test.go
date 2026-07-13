package monitor

import (
	"os"
	"runtime"
	"testing"
)

func TestEndpointPacketUsesIPv4PacketLength(t *testing.T) {
	var pending int64
	if _, _, _, _, ok := endpointPacket("1700000000.1 IP (tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto UDP (17), length 1280)", &pending); ok {
		t.Fatal("metadata line must not produce a packet")
	}
	port, host, clientPort, size, ok := endpointPacket("    192.0.2.10.45080 > 198.51.100.20.54321: UDP, length 1252", &pending)
	if !ok || port != 45080 || host != "198.51.100.20" || clientPort != "54321" || size != 1280 {
		t.Fatalf("unexpected IPv4 packet: %d %q %q %d %v", port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketIncludesIPv6Header(t *testing.T) {
	var pending int64
	endpointPacket("1700000000.2 IP6 (flowlabel 0x1, hlim 64, next-header UDP (17) payload length: 1240)", &pending)
	port, host, clientPort, size, ok := endpointPacket("    2001:db8::1.45081 > 2001:db8::2.54322: UDP, length 1232", &pending)
	if !ok || port != 45081 || host != "2001:db8::2" || clientPort != "54322" || size != 1280 {
		t.Fatalf("unexpected IPv6 packet: %d %q %q %d %v", port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketRejectsLineWithoutLengthMetadata(t *testing.T) {
	var pending int64
	if _, _, _, _, ok := endpointPacket("192.0.2.10.45080 > 198.51.100.20.54321: UDP, length 100", &pending); ok {
		t.Fatal("endpoint without IP packet length metadata must be ignored")
	}
}

func TestEndpointPacketParsesAlpineSingleLineIPv6(t *testing.T) {
	var pending int64
	line := "1783909462.501781 eth0 Out IP6 (flowlabel 0x92a6f, hlim 64, next-header UDP (17) payload length: 1288) 2a01:db8::1.55119 > 2602:db8::2.56681: UDP, length 1280"
	port, host, clientPort, size, ok := endpointPacket(line, &pending)
	if !ok || port != 55119 || host != "2602:db8::2" || clientPort != "56681" || size != 1328 {
		t.Fatalf("unexpected Alpine IPv6 packet: %d %q %q %d %v", port, host, clientPort, size, ok)
	}
}

func TestEndpointPacketParsesAlpineSingleLineIPv4(t *testing.T) {
	var pending int64
	line := "1783909462.501781 eth0 Out IP (tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto UDP (17), length 1280) 192.0.2.10.45115 > 198.51.100.20.56681: UDP, length 1252"
	port, host, clientPort, size, ok := endpointPacket(line, &pending)
	if !ok || port != 45115 || host != "198.51.100.20" || clientPort != "56681" || size != 1280 {
		t.Fatalf("unexpected Alpine IPv4 packet: %d %q %q %d %v", port, host, clientPort, size, ok)
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

func TestProcessSnapshotOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}
	collector := &Collector{lastProcessCPU: map[int]uint64{}}
	items, count := collector.processSnapshot(1_000_000_000)
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

func TestUDPEndpointProtocolFilter(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic", "shadowsocks"} {
		if !udpEndpointProtocol(protocol) {
			t.Fatalf("UDP endpoint protocol %s was excluded", protocol)
		}
	}
	for _, protocol := range []string{"vless", "trojan", "unknown"} {
		if udpEndpointProtocol(protocol) {
			t.Fatalf("TCP-only protocol %s was included in UDP capture", protocol)
		}
	}
}
