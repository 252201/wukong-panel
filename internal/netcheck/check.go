package netcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
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
	samplesPerTarget = 5
	sampleGap        = 150 * time.Millisecond
	replyTimeout     = 900 * time.Millisecond
	refreshInterval  = 60 * time.Second
)

const defaultTargets = "1.1.1.1,8.8.8.8"
const defaultDomesticTargets = "194.138.202.35,138.113.151.2"

const (
	internationalGroup = "international"
	domesticGroup      = "domestic"
)

// Keep an extra minute so the UI can show 30 complete probe intervals even
// when the newest probe is nearly a minute old.
const historyRetentionWindow = 31 * time.Minute

type historyStore interface {
	AddNetworkSample(string, model.NetworkSample) error
	RecentNetworkSamples(string, time.Time, int) ([]model.NetworkSample, error)
}

type targetResult struct {
	sent       int
	received   int
	roundTrips []time.Duration
	err        error
}

type targetProbe func(context.Context, net.IP) targetResult

type icmpSocket interface {
	Close() error
	LocalAddr() net.Addr
	WriteTo([]byte, net.Addr) (int, error)
	ReadFrom([]byte) (int, net.Addr, error)
	SetReadDeadline(time.Time) error
}

type socketListener func(string, string) (icmpSocket, error)

// Service keeps one recent outbound ICMP measurement for this VPS. Probes run
// in the root agent or lightweight probe; the web process only reads snapshots.
type Service struct {
	targets          []net.IP
	labels           []string
	setupErr         error
	domesticTargets  []net.IP
	domesticLabels   []string
	domesticSetupErr error
	demo             bool
	store            historyStore
	probe            targetProbe

	mu              sync.RWMutex
	current         *model.NetworkHealth
	history         []model.NetworkSample
	domesticHistory []model.NetworkSample
}

func NewService(rawTargets, rawDomesticTargets string, demo bool, repository historyStore) *Service {
	if strings.TrimSpace(rawTargets) == "" {
		rawTargets = defaultTargets
	}
	if strings.TrimSpace(rawDomesticTargets) == "" {
		rawDomesticTargets = defaultDomesticTargets
	}
	targets, labels, err := parseTargets(rawTargets)
	domesticTargets, domesticLabels, domesticErr := parseTargets(rawDomesticTargets)
	service := &Service{targets: targets, labels: labels, setupErr: err,
		domesticTargets: domesticTargets, domesticLabels: domesticLabels,
		domesticSetupErr: domesticErr, demo: demo, store: repository, probe: probeTarget}
	if demo {
		service.history = demoHistory(time.Now().UTC(), labels, false)
		service.domesticHistory = demoHistory(time.Now().UTC(), domesticLabels, true)
	} else if repository != nil {
		service.history, err = repository.RecentNetworkSamples(internationalGroup, time.Now().Add(-historyRetentionWindow), 60)
		if err != nil {
			log.Printf("international network history unavailable: %v", err)
		}
		service.domesticHistory, err = repository.RecentNetworkSamples(domesticGroup, time.Now().Add(-historyRetentionWindow), 60)
		if err != nil {
			log.Printf("domestic network history unavailable: %v", err)
		}
	}
	return service
}

func parseTargets(raw string) ([]net.IP, []string, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
	targets := make([]net.IP, 0, len(parts))
	labels := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		ip := net.ParseIP(strings.TrimSpace(part)).To4()
		if ip == nil {
			return nil, nil, fmt.Errorf("探测目标必须是 IPv4 地址：%q", part)
		}
		label := ip.String()
		if seen[label] {
			continue
		}
		if len(targets) == 4 {
			return nil, nil, errors.New("最多配置 4 个探测目标")
		}
		seen[label] = true
		targets = append(targets, ip)
		labels = append(labels, label)
	}
	if len(targets) == 0 {
		return nil, nil, errors.New("至少配置 1 个探测目标")
	}
	return targets, labels, nil
}

func (s *Service) Current() *model.NetworkHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil
	}
	copy := *s.current
	copy.Targets = append([]string(nil), s.current.Targets...)
	copy.TargetResults = append([]model.NetworkTargetResult(nil), s.current.TargetResults...)
	copy.History = recentCopy(s.history)
	copy.International = groupHealth(copy, copy.History)
	if s.current.Domestic != nil {
		domestic := *s.current.Domestic
		domestic.Targets = append([]string(nil), domestic.Targets...)
		domestic.TargetResults = append([]model.NetworkTargetResult(nil), domestic.TargetResults...)
		domestic.History = recentCopy(s.domesticHistory)
		copy.Domestic = &domestic
	}
	return &copy
}

func recentCopy(history []model.NetworkSample) []model.NetworkSample {
	result := make([]model.NetworkSample, 0, len(history))
	cutoff := time.Now().Add(-historyRetentionWindow)
	for _, sample := range history {
		if sample.CheckedAt.Before(cutoff) {
			continue
		}
		item := sample
		item.Targets = append([]string(nil), sample.Targets...)
		item.TargetResults = append([]model.NetworkTargetResult(nil), sample.TargetResults...)
		result = append(result, item)
	}
	return result
}

func groupHealth(health model.NetworkHealth, history []model.NetworkSample) *model.NetworkGroupHealth {
	return &model.NetworkGroupHealth{
		Status: health.Status, LatencyMS: health.LatencyMS,
		PacketLossPct: health.PacketLossPct, PacketsSent: health.PacketsSent,
		PacketsReceived: health.PacketsReceived, Targets: append([]string(nil), health.Targets...),
		TargetResults: append([]model.NetworkTargetResult(nil), health.TargetResults...),
		CheckedAt:     health.CheckedAt, Error: health.Error, History: history,
	}
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		probeStartedAt := time.Now().UTC()
		type groupResult struct {
			name   string
			health model.NetworkHealth
		}
		results := make(chan groupResult, 2)
		go func() {
			results <- groupResult{internationalGroup, s.measureGroup(ctx, s.targets, s.labels, s.setupErr, false)}
		}()
		go func() {
			results <- groupResult{domesticGroup, s.measureGroup(ctx, s.domesticTargets, s.domesticLabels, s.domesticSetupErr, true)}
		}()
		first, second := <-results, <-results
		international, domestic := first.health, second.health
		if first.name == domesticGroup {
			international, domestic = second.health, first.health
		}
		// The two groups belong to the same scheduled probe cycle. Timestamp
		// them at its start, independent of ICMP completion time.
		international.CheckedAt = probeStartedAt
		domestic.CheckedAt = probeStartedAt
		domesticGroupHealth := groupHealth(domestic, nil)
		international.Domestic = domesticGroupHealth
		international.Demo = s.demo
		internationalSample := sampleOf(international)
		domesticSample := sampleOf(domestic)
		if s.store != nil && !s.demo {
			if err := s.store.AddNetworkSample(internationalGroup, internationalSample); err != nil {
				log.Printf("international network history save failed: %v", err)
			}
			if err := s.store.AddNetworkSample(domesticGroup, domesticSample); err != nil {
				log.Printf("domestic network history save failed: %v", err)
			}
		}
		s.mu.Lock()
		s.current = &international
		s.history = appendRecent(s.history, internationalSample)
		s.domesticHistory = appendRecent(s.domesticHistory, domesticSample)
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) measureGroup(ctx context.Context, targets []net.IP, labels []string, setupErr error, domestic bool) model.NetworkHealth {
	if setupErr != nil {
		return model.NetworkHealth{Status: "error", Error: setupErr.Error(), CheckedAt: time.Now().UTC()}
	}
	if s.demo {
		packetCount := samplesPerTarget * len(labels)
		if domestic {
			return model.NetworkHealth{Status: "ok", LatencyMS: 162.4, PacketsSent: packetCount, PacketsReceived: packetCount, CheckedAt: time.Now().UTC(), Targets: append([]string(nil), labels...), TargetResults: demoTargetResults(labels, 0)}
		}
		lost := min(1, packetCount)
		return model.NetworkHealth{Status: "ok", LatencyMS: 41.8, PacketLossPct: float64(lost) * 100 / float64(packetCount), PacketsSent: packetCount, PacketsReceived: packetCount - lost, CheckedAt: time.Now().UTC(), Targets: append([]string(nil), labels...), TargetResults: demoTargetResults(labels, lost)}
	}
	return measure(ctx, targets, labels, s.probe)
}

func appendRecent(history []model.NetworkSample, sample model.NetworkSample) []model.NetworkSample {
	history = append(history, sample)
	cutoff := sample.CheckedAt.Add(-historyRetentionWindow)
	for len(history) > 0 && history[0].CheckedAt.Before(cutoff) {
		history = history[1:]
	}
	if len(history) > 60 {
		history = history[len(history)-60:]
	}
	return history
}

func sampleOf(health model.NetworkHealth) model.NetworkSample {
	return model.NetworkSample{
		Status: health.Status, LatencyMS: health.LatencyMS,
		PacketLossPct: health.PacketLossPct, PacketsSent: health.PacketsSent,
		PacketsReceived: health.PacketsReceived,
		Targets:         append([]string(nil), health.Targets...),
		TargetResults:   append([]model.NetworkTargetResult(nil), health.TargetResults...), CheckedAt: health.CheckedAt,
	}
}

func demoHistory(now time.Time, targets []string, domestic bool) []model.NetworkSample {
	if len(targets) == 0 {
		return nil
	}
	result := make([]model.NetworkSample, 0, 29)
	for minute := 29; minute >= 1; minute-- {
		loss := 0.0
		if domestic && minute%19 == 0 {
			loss = 10
		} else if !domestic && minute%11 == 0 {
			loss = 10
		} else if !domestic && minute%7 == 0 {
			loss = 20
		}
		latency := float64(35 + (minute*7)%31)
		if domestic {
			latency = float64(150 + (minute*7)%31)
		}
		sent := samplesPerTarget * len(targets)
		lost := int(math.Round(loss * float64(sent) / 100))
		actualLoss := float64(lost) * 100 / float64(sent)
		result = append(result, model.NetworkSample{
			Status: "ok", LatencyMS: latency, PacketLossPct: actualLoss,
			PacketsSent: sent, PacketsReceived: sent - lost,
			Targets: append([]string(nil), targets...), TargetResults: demoTargetResults(targets, lost), CheckedAt: now.Add(-time.Duration(minute) * time.Minute),
		})
	}
	return result
}

func demoTargetResults(targets []string, lost int) []model.NetworkTargetResult {
	results := make([]model.NetworkTargetResult, len(targets))
	for index, target := range targets {
		dropped := min(samplesPerTarget, lost)
		results[index] = model.NetworkTargetResult{Target: target, PacketsSent: samplesPerTarget, PacketsReceived: samplesPerTarget - dropped}
		lost -= dropped
	}
	return results
}

func measure(ctx context.Context, targets []net.IP, labels []string, probe targetProbe) (health model.NetworkHealth) {
	health = model.NetworkHealth{Status: "error", Targets: append([]string(nil), labels...)}
	defer func() { health.CheckedAt = time.Now().UTC() }()
	if len(targets) == 0 {
		health.Error = "没有可用的探测目标"
		return health
	}
	type indexedResult struct {
		index int
		value targetResult
	}
	results := make(chan indexedResult, len(targets))
	health.TargetResults = make([]model.NetworkTargetResult, len(targets))
	for index, target := range targets {
		go func(index int, ip net.IP) { results <- indexedResult{index, probe(ctx, ip)} }(index, target)
	}
	var roundTrips []time.Duration
	var failures []string
	for range targets {
		entry := <-results
		result := entry.value
		health.TargetResults[entry.index] = model.NetworkTargetResult{
			Target: labels[entry.index], PacketsSent: result.sent, PacketsReceived: result.received,
		}
		health.PacketsSent += result.sent
		health.PacketsReceived += result.received
		roundTrips = append(roundTrips, result.roundTrips...)
		if result.err != nil {
			failures = append(failures, result.err.Error())
		}
	}
	if health.PacketsSent == 0 {
		health.Error = strings.Join(failures, "; ")
		if health.Error == "" {
			health.Error = "没有发出 ICMP 探测包"
		}
		return health
	}
	health.Status = "ok"
	if len(failures) > 0 {
		health.Status = "partial"
		health.Error = strings.Join(failures, "; ")
	}
	health.PacketLossPct = math.Round(float64(health.PacketsSent-health.PacketsReceived)*1000/float64(health.PacketsSent)) / 10
	health.LatencyMS = medianMS(roundTrips)
	return health
}

func medianMS(samples []time.Duration) float64 {
	if len(samples) == 0 {
		return 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	middle := len(samples) / 2
	median := samples[middle]
	if len(samples)%2 == 0 {
		median = (samples[middle-1] + samples[middle]) / 2
	}
	return math.Round(float64(median)/float64(time.Millisecond)*10) / 10
}

func probeTarget(ctx context.Context, target net.IP) targetResult {
	return probeTargetWithListener(ctx, target, func(network, address string) (icmpSocket, error) {
		return icmp.ListenPacket(network, address)
	})
}

func probeTargetWithListener(ctx context.Context, target net.IP, listen socketListener) targetResult {
	var result targetResult
	conn, err := listen("ip4:icmp", "0.0.0.0")
	datagram := false
	if err != nil {
		rawErr := err
		conn, err = listen("udp4", "0.0.0.0")
		if err != nil {
			result.err = fmt.Errorf("%s: 无法打开 ICMP socket（原始: %v；非特权: %w）", target, rawErr, err)
			return result
		}
		datagram = true
	}
	defer conn.Close()
	var token [8]byte
	if _, err = rand.Read(token[:]); err != nil {
		result.err = err
		return result
	}
	id := int(binary.BigEndian.Uint16(token[:2]))
	var destination net.Addr = &net.IPAddr{IP: target}
	if datagram {
		// Linux assigns the bound ping socket's port as the Echo ID and
		// rewrites outgoing IDs. Match that ID as well as our random payload
		// and sequence, otherwise valid non-privileged replies look lost.
		local, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok || local == nil || local.Port <= 0 || local.Port > 65535 {
			result.err = fmt.Errorf("%s: 无法确定非特权 ICMP socket 标识", target)
			return result
		}
		id = local.Port
		destination = &net.UDPAddr{IP: target}
	}
	buffer := make([]byte, 1500)
	for sequence := 0; sequence < samplesPerTarget; sequence++ {
		if err := ctx.Err(); err != nil {
			result.err = err
			return result
		}
		message := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: sequence, Data: token[:]}}
		packet, err := message.Marshal(nil)
		if err != nil {
			result.err = err
			return result
		}
		started := time.Now()
		if _, err = conn.WriteTo(packet, destination); err != nil {
			result.err = fmt.Errorf("%s: 发送 ICMP 失败: %w", target, err)
			return result
		}
		result.sent++
		deadline := started.Add(replyTimeout)
		for {
			if err = conn.SetReadDeadline(deadline); err != nil {
				result.sent--
				result.err = err
				return result
			}
			n, sender, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					break
				}
				result.err = fmt.Errorf("%s: 读取 ICMP 失败: %w", target, readErr)
				result.sent--
				return result
			}
			var senderIP net.IP
			switch address := sender.(type) {
			case *net.IPAddr:
				senderIP = address.IP
			case *net.UDPAddr:
				senderIP = address.IP
			}
			if !senderIP.Equal(target) {
				continue
			}
			reply, parseErr := icmp.ParseMessage(1, buffer[:n])
			if parseErr != nil || reply.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := reply.Body.(*icmp.Echo)
			if !ok || echo.ID != id || echo.Seq != sequence || !bytes.Equal(echo.Data, token[:]) {
				continue
			}
			result.received++
			result.roundTrips = append(result.roundTrips, time.Since(started))
			break
		}
		if sequence+1 < samplesPerTarget {
			timer := time.NewTimer(sampleGap)
			select {
			case <-ctx.Done():
				timer.Stop()
				result.err = ctx.Err()
				return result
			case <-timer.C:
			}
		}
	}
	return result
}
