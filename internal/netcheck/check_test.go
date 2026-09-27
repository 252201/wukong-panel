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
	samples map[string][]model.NetworkSample
}

func (f *fakeHistoryStore) AddNetworkSample(group string, sample model.NetworkSample) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.samples == nil {
		f.samples = make(map[string][]model.NetworkSample)
	}
	f.samples[group] = append(f.samples[group], sample)
	return nil
}

func (f *fakeHistoryStore) RecentNetworkSamples(group string, _ time.Time, _ int) ([]model.NetworkSample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.NetworkSample(nil), f.samples[group]...), nil
}

func (f *fakeHistoryStore) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.samples[internationalGroup]) + len(f.samples[domesticGroup])
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

func TestDefaultDomesticTarget(t *testing.T) {
	service := NewService("", "", false, nil)
	if got := strings.Join(service.domesticLabels, ","); got != "194.138.202.35,138.113.151.2" {
		t.Fatalf("domestic default targets = %q", got)
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
	if len(health.TargetResults) != 2 || health.TargetResults[0] != (model.NetworkTargetResult{Target: "1.1.1.1", PacketsSent: 5, PacketsReceived: 4}) || health.TargetResults[1] != (model.NetworkTargetResult{Target: "8.8.8.8", PacketsSent: 5, PacketsReceived: 5}) {
		t.Fatalf("per-target loss was not preserved in target order: %+v", health.TargetResults)
	}
}

func TestMeasureKeepsConfiguredTargetOrderWhenRepliesFinishOutOfOrder(t *testing.T) {
	targets, labels, _ := parseTargets("1.1.1.1,8.8.8.8")
	health := measure(context.Background(), targets, labels, func(_ context.Context, ip net.IP) targetResult {
		if ip.String() == "1.1.1.1" {
			time.Sleep(10 * time.Millisecond)
			return targetResult{sent: 5, received: 5}
		}
		return targetResult{sent: 5, received: 3}
	})
	if health.TargetResults[0].Target != "1.1.1.1" || health.TargetResults[0].PacketsReceived != 5 || health.TargetResults[1].Target != "8.8.8.8" || health.TargetResults[1].PacketsReceived != 3 {
		t.Fatalf("results did not follow configured target order: %+v", health.TargetResults)
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
	service := NewService("1.1.1.1", "194.138.202.35", true, nil)
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
	first.Domestic.Targets[0] = "changed"
	first.Domestic.History[0].Targets[0] = "changed"
	first.TargetResults[0].Target = "changed"
	first.History[0].TargetResults[0].Target = "changed"
	first.Domestic.TargetResults[0].Target = "changed"
	first.Domestic.History[0].TargetResults[0].Target = "changed"
	if service.Current().Targets[0] != "1.1.1.1" {
		t.Fatal("Current shared mutable targets")
	}
	if service.Current().History[0].Targets[0] != "1.1.1.1" {
		t.Fatal("Current shared mutable history")
	}
	if service.Current().Domestic.Targets[0] != "194.138.202.35" || service.Current().Domestic.History[0].Targets[0] != "194.138.202.35" {
		t.Fatal("Current shared mutable domestic data")
	}
	if service.Current().TargetResults[0].Target != "1.1.1.1" || service.Current().History[0].TargetResults[0].Target != "1.1.1.1" || service.Current().Domestic.TargetResults[0].Target != "194.138.202.35" || service.Current().Domestic.History[0].TargetResults[0].Target != "194.138.202.35" {
		t.Fatal("Current shared mutable per-target results")
	}
}

func TestServiceRestoresAndRecordsHistory(t *testing.T) {
	repository := &fakeHistoryStore{samples: map[string][]model.NetworkSample{
		internationalGroup: {{Status: "ok", CheckedAt: time.Now().Add(-time.Minute), Targets: []string{"1.1.1.1"}}},
		domesticGroup:      {{Status: "ok", CheckedAt: time.Now().Add(-time.Minute), Targets: []string{"194.138.202.35"}}},
	}}
	service := NewService("invalid-target", "invalid-domestic", false, repository)
	if len(service.history) != 1 || len(service.domesticHistory) != 1 {
		t.Fatalf("group histories were not restored: %+v %+v", service.history, service.domesticHistory)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.Run(ctx)
	deadline := time.Now().Add(time.Second)
	for (repository.Count() < 4 || service.Current() == nil) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	current := service.Current()
	if current == nil || current.Status != "error" || current.Domestic.Status != "error" || len(current.History) != 2 || len(current.Domestic.History) != 2 || repository.Count() != 4 {
		t.Fatalf("new measurement was not stored: current=%+v count=%d", current, repository.Count())
	}
}

func TestServiceMeasuresGroupsIndependently(t *testing.T) {
	repository := &fakeHistoryStore{}
	service := NewService("1.1.1.1", "194.138.202.35", false, repository)
	service.probe = func(_ context.Context, ip net.IP) targetResult {
		if ip.String() == "1.1.1.1" {
			return targetResult{sent: 5, received: 5, roundTrips: []time.Duration{20 * time.Millisecond}}
		}
		return targetResult{sent: 5, received: 4, roundTrips: []time.Duration{160 * time.Millisecond}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.Run(ctx)
	deadline := time.Now().Add(time.Second)
	for (repository.Count() < 2 || service.Current() == nil) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	current := service.Current()
	if current == nil || current.PacketLossPct != 0 || current.LatencyMS != 20 || current.Domestic.PacketLossPct != 20 || current.Domestic.LatencyMS != 160 {
		t.Fatalf("groups were combined: %+v", current)
	}
	if current.International.Targets[0] != "1.1.1.1" || current.Domestic.Targets[0] != "194.138.202.35" {
		t.Fatalf("group targets were crossed: %+v", current)
	}
	if !current.CheckedAt.Equal(current.International.CheckedAt) || !current.CheckedAt.Equal(current.Domestic.CheckedAt) {
		t.Fatalf("groups in one probe cycle have different timestamps: %+v", current)
	}
}

func TestDomesticConfigurationErrorDoesNotHideInternationalResult(t *testing.T) {
	service := NewService("1.1.1.1", "invalid-domestic", false, nil)
	service.probe = func(context.Context, net.IP) targetResult {
		return targetResult{sent: 5, received: 5, roundTrips: []time.Duration{25 * time.Millisecond}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.Run(ctx)
	deadline := time.Now().Add(time.Second)
	for service.Current() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	current := service.Current()
	if current == nil || current.Status != "ok" || current.LatencyMS != 25 || current.Domestic == nil || current.Domestic.Status != "error" || len(current.Domestic.History) != 1 {
		t.Fatalf("domestic configuration masked international result: %+v", current)
	}
}
