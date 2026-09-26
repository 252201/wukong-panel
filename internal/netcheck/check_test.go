package netcheck

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

type fakeHistoryStore struct {
	mu      sync.Mutex
	samples []model.NetworkSample
}

func (f *fakeHistoryStore) AddNetworkSample(sample model.NetworkSample) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.samples = append(f.samples, sample)
	return nil
}

func (f *fakeHistoryStore) RecentNetworkSamples(time.Time, int) ([]model.NetworkSample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.NetworkSample(nil), f.samples...), nil
}

func (f *fakeHistoryStore) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.samples)
}

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
	service := NewService("1.1.1.1", true, nil)
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
	first.History[0].Targets[0] = "changed"
	if service.Current().Targets[0] != "1.1.1.1" {
		t.Fatal("Current shared mutable targets")
	}
	if service.Current().History[0].Targets[0] != "1.1.1.1" {
		t.Fatal("Current shared mutable history")
	}
}

func TestServiceRestoresAndRecordsHistory(t *testing.T) {
	repository := &fakeHistoryStore{samples: []model.NetworkSample{{Status: "ok", CheckedAt: time.Now().Add(-time.Minute), Targets: []string{"1.1.1.1"}}}}
	service := NewService("invalid-target", false, repository)
	if len(service.history) != 1 {
		t.Fatalf("history was not restored: %+v", service.history)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.Run(ctx)
	deadline := time.Now().Add(time.Second)
	for (repository.Count() < 2 || service.Current() == nil) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	current := service.Current()
	if current == nil || current.Status != "error" || len(current.History) != 2 || repository.Count() != 2 {
		t.Fatalf("new measurement was not stored: current=%+v count=%d", current, repository.Count())
	}
}
