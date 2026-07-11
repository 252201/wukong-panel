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
