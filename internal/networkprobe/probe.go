package networkprobe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	SampleCount    = 20
	SampleInterval = 200 * time.Millisecond
	ResponseWait   = 1500 * time.Millisecond
	ProbeInterval  = 60 * time.Second
)

var ErrNotReady = errors.New("network probe has not completed")

var defaultTargets = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

// DefaultTargets returns the public IPv4 targets used by a new installation.
// A copy is returned so callers cannot mutate the package defaults.
func DefaultTargets() []string {
	return append([]string(nil), defaultTargets...)
}

// ParseTargets parses the comma-separated target list used by the environment
// variable and removes empty or duplicate entries.
func ParseTargets(raw string) []string {
	items := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' ' })
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

// State stores the most recent probe result for the local VPS. It is shared
// by the root agent, the fleet heartbeat, and the local web process through
// the agent RPC transport.
type State struct {
	targets []string

	mu     sync.RWMutex
	health model.FleetNetworkHealth
}

func NewState(targets []string) *State {
	targets = ParseTargets(strings.Join(targets, ","))
	if len(targets) == 0 {
		targets = DefaultTargets()
	}
	return &State{targets: targets}
}

func (s *State) Health() (model.FleetNetworkHealth, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.health, !s.health.CheckedAt.IsZero()
}

// Run performs one fixed-size sample window immediately after the initial
// startup delay and refreshes it periodically. Every sample is sent by this
// VPS directly to the configured public targets; the controller is not part
// of the measurement path.
func (s *State) Run(ctx context.Context) {
	initial := time.NewTimer(5 * time.Second)
	defer initial.Stop()
	select {
	case <-ctx.Done():
		return
	case <-initial.C:
	}

	for ctx.Err() == nil {
		health := Probe(ctx, s.targets)
		s.mu.Lock()
		s.health = health
		s.mu.Unlock()

		timer := time.NewTimer(ProbeInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type targetResult struct {
	sent      int
	received  int
	latencies []time.Duration
	samples   []targetSample
	err       error
}

type targetSample struct {
	sent     int
	received int
	latency  time.Duration
}

// Probe sends SampleCount ICMP echo requests to every configured target. The
// packet-loss percentage is computed from this exact sample window, while
// latency is the median of the successful round trips.
func Probe(ctx context.Context, targets []string) model.FleetNetworkHealth {
	targets = ParseTargets(strings.Join(targets, ","))
	checkedAt := time.Now().UTC()
	result := model.FleetNetworkHealth{Status: "error", CheckedAt: checkedAt}
	if len(targets) == 0 {
		result.Error = "network probe has no targets"
		return result
	}

	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(SampleCount)*SampleInterval+ResponseWait+time.Second)
	defer cancel()
	results := make(chan targetResult, len(targets))
	for _, target := range targets {
		go func(target string) {
			results <- probeTarget(probeCtx, target)
		}(target)
	}

	latencies := make([]time.Duration, 0, len(targets)*SampleCount)
	sampleLatencies := make([][]time.Duration, SampleCount)
	samples := make([]model.FleetNetworkSample, SampleCount)
	var errorsFound []string
	for range targets {
		current := <-results
		result.PacketsSent += current.sent
		result.PacketsReceived += current.received
		latencies = append(latencies, current.latencies...)
		for sequence, sample := range current.samples {
			if sequence >= len(samples) {
				break
			}
			samples[sequence].PacketsSent += sample.sent
			samples[sequence].PacketsReceived += sample.received
			if sample.received > 0 {
				sampleLatencies[sequence] = append(sampleLatencies[sequence], sample.latency)
			}
		}
		if current.err != nil {
			errorsFound = append(errorsFound, current.err.Error())
		}
	}
	for sequence := range samples {
		samples[sequence].LatencyMS = medianMilliseconds(sampleLatencies[sequence])
	}
	if result.PacketsSent == 0 {
		result.Error = strings.Join(errorsFound, "; ")
		if result.Error == "" {
			result.Error = "network probe did not send any packets"
		}
		return result
	}

	result.Status = "ok"
	result.PacketLossPct = float64(result.PacketsSent-result.PacketsReceived) * 100 / float64(result.PacketsSent)
	result.LatencyMS = medianMilliseconds(latencies)
	result.Samples = samples
	if len(errorsFound) > 0 {
		result.Error = strings.Join(errorsFound, "; ")
	}
	return result
}

func probeTarget(ctx context.Context, target string) targetResult {
	address, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return targetResult{err: fmt.Errorf("%s: resolve target: %w", target, err)}
	}
	ip := address.IP.To4()
	if ip == nil {
		return targetResult{err: fmt.Errorf("%s: target is not an IPv4 address", target)}
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return targetResult{err: fmt.Errorf("%s: open ICMP socket: %w", target, err)}
	}
	defer conn.Close()

	id := int(time.Now().UnixNano() & 0xffff)
	sentAt := make(map[int]time.Time, SampleCount)
	result := targetResult{
		latencies: make([]time.Duration, 0, SampleCount),
		samples:   make([]targetSample, SampleCount),
	}
	for sequence := 0; sequence < SampleCount; sequence++ {
		if err := ctx.Err(); err != nil {
			return resultWithError(result, err)
		}
		message := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: sequence, Data: []byte("wukong-network-probe")},
		}
		packet, err := message.Marshal(nil)
		if err != nil {
			return resultWithError(result, fmt.Errorf("%s: encode ICMP packet: %w", target, err))
		}
		if _, err = conn.WriteTo(packet, &net.IPAddr{IP: ip}); err != nil {
			return resultWithError(result, fmt.Errorf("%s: send ICMP packet: %w", target, err))
		}
		sentAt[sequence] = time.Now()
		result.sent++
		result.samples[sequence].sent = 1
		if sequence+1 < SampleCount {
			timer := time.NewTimer(SampleInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return resultWithError(result, ctx.Err())
			case <-timer.C:
			}
		}
	}

	deadline := time.Now().Add(ResponseWait)
	seen := make(map[int]struct{}, SampleCount)
	buffer := make([]byte, 1500)
	for result.received < result.sent {
		if err := ctx.Err(); err != nil {
			return resultWithError(result, err)
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return resultWithError(result, fmt.Errorf("%s: set ICMP deadline: %w", target, err))
		}
		n, _, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				break
			}
			return resultWithError(result, fmt.Errorf("%s: read ICMP response: %w", target, readErr))
		}
		message, parseErr := icmp.ParseMessage(1, buffer[:n])
		if parseErr != nil || message.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := message.Body.(*icmp.Echo)
		if !ok || echo.ID != id {
			continue
		}
		if _, ok := seen[echo.Seq]; ok {
			continue
		}
		sent, ok := sentAt[echo.Seq]
		if !ok {
			continue
		}
		seen[echo.Seq] = struct{}{}
		result.received++
		latency := time.Since(sent)
		result.latencies = append(result.latencies, latency)
		result.samples[echo.Seq].received = 1
		result.samples[echo.Seq].latency = latency
	}
	return result
}

func resultWithError(result targetResult, err error) targetResult {
	if err != nil {
		result.err = err
	}
	return result
}

func medianMilliseconds(values []time.Duration) int64 {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	median := values[len(values)/2]
	if len(values)%2 == 0 {
		median = (values[len(values)/2-1] + values[len(values)/2]) / 2
	}
	return int64(math.Round(float64(median) / float64(time.Millisecond)))
}
