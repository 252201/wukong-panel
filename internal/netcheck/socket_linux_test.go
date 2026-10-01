//go:build linux

package netcheck

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/icmp"
)

// Run explicitly in an isolated Linux container with or without NET_RAW:
// WUKONG_TEST_ICMP_MODE=raw|datagram|unavailable go test ./internal/netcheck -run TestLinuxICMPLoopback
func TestLinuxICMPLoopback(t *testing.T) {
	mode := os.Getenv("WUKONG_TEST_ICMP_MODE")
	if mode == "" {
		t.Skip("requires explicit Linux socket integration test opt-in")
	}
	if mode != "raw" && mode != "datagram" && mode != "unavailable" {
		t.Fatalf("invalid ICMP mode %q", mode)
	}
	raw, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		raw.Close()
	}
	if (mode == "raw" && err != nil) || (mode != "raw" && err == nil) {
		t.Fatalf("raw socket availability does not match mode %q: %v", mode, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Concurrent targets exercise kernel-assigned Echo IDs and reply isolation.
	targets, labels, _ := parseTargets("127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4")
	health := measure(ctx, targets, labels, probeTarget)
	if mode == "unavailable" {
		if health.Status != "error" || health.PacketsSent != 0 || health.PacketsReceived != 0 || health.PacketLossPct != 0 || health.Error == "" {
			t.Fatalf("socket denial was reported as packet loss: %+v", health)
		}
		t.Logf("both socket modes denied: status=%s sent=%d loss=%.1f%%", health.Status, health.PacketsSent, health.PacketLossPct)
		return
	}
	if health.Status != "ok" || health.PacketsSent != 20 || health.PacketsReceived != 20 || health.PacketLossPct != 0 {
		t.Fatalf("real %s ICMP loopback failed: %+v", mode, health)
	}
	for _, result := range health.TargetResults {
		if net.ParseIP(result.Target) == nil || result.PacketsSent != 5 || result.PacketsReceived != 5 {
			t.Fatalf("unexpected per-target counters: %+v", result)
		}
	}
	t.Logf("mode=%s sent=%d received=%d loss=%.1f%% latency=%.1fms", mode, health.PacketsSent, health.PacketsReceived, health.PacketLossPct, health.LatencyMS)
}
