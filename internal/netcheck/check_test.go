package netcheck

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	targets, labels, err := parseTargets(" 1.1.1.1, 8.8.8.8,1.1.1.1 ")
	if err != nil || len(targets) != 2 || strings.Join(labels, ",") != "1.1.1.1,8.8.8.8" {
		t.Fatalf("targets=%v labels=%v err=%v", targets, labels, err)
	}
	for _, input := range []string{"", "example.com", "2001:4860:4860::8888", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5"} {
		if _, _, err := parseTargets(input); err == nil {
			t.Fatalf("parseTargets(%q) accepted invalid configuration", input)
		}
	}
}

func TestMeasureAggregatesReplies(t *testing.T) {
	targets, labels, _ := parseTargets("1.1.1.1,8.8.8.8")
	probe := func(_ context.Context, ip net.IP) targetResult {
		if ip.String() == "1.1.1.1" {
			return targetResult{sent: 5, received: 4, roundTrips: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond}}
		}
		return targetResult{sent: 5, received: 5, roundTrips: []time.Duration{50 * time.Millisecond, 60 * time.Millisecond, 70 * time.Millisecond, 80 * time.Millisecond, 90 * time.Millisecond}}
	}
	health := measure(context.Background(), targets, labels, probe)
	if health.Status != "ok" || health.PacketsSent != 10 || health.PacketsReceived != 9 || health.PacketLossPct != 10 || health.LatencyMS != 50 {
		t.Fatalf("unexpected health: %+v", health)
	}
}

func TestMeasureDoesNotCallSocketFailurePacketLoss(t *testing.T) {
	targets, labels, _ := parseTargets("1.1.1.1")
	health := measure(context.Background(), targets, labels, func(context.Context, net.IP) targetResult {
		return targetResult{err: errors.New("permission denied")}
	})
	if health.Status != "error" || health.PacketsSent != 0 || health.PacketLossPct != 0 || !strings.Contains(health.Error, "permission denied") {
		t.Fatalf("socket failure was treated as packet loss: %+v", health)
	}
}

func TestMeasureAllSentWithoutRepliesIsFullLoss(t *testing.T) {
	targets, labels, _ := parseTargets("1.1.1.1")
	health := measure(context.Background(), targets, labels, func(context.Context, net.IP) targetResult {
		return targetResult{sent: 5}
	})
	if health.Status != "ok" || health.PacketLossPct != 100 || health.LatencyMS != 0 {
		t.Fatalf("no replies should show full loss: %+v", health)
	}
}

func TestCurrentReturnsDefensiveCopy(t *testing.T) {
	service := NewService("1.1.1.1", true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.Run(ctx)
	deadline := time.Now().Add(time.Second)
	for service.Current() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	first := service.Current()
	if first == nil {
		t.Fatal("demo service did not produce a sample")
	}
	first.Targets[0] = "changed"
	if service.Current().Targets[0] != "1.1.1.1" {
		t.Fatal("Current shared mutable targets")
	}
}
