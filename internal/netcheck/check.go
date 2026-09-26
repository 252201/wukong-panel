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
const defaultDomesticTargets = "194.138.202.35,159.27.255.225"

const (
	internationalGroup = "international"
	domesticGroup      = "domestic"
)

const historyWindow = 30 * time.Minute

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

// Service keeps one recent outbound ICMP measurement for this VPS. Probes run
// in the local root agent; the web process only reads the resulting snapshot.
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
		service.history, err = repository.RecentNetworkSamples(internationalGroup, time.Now().Add(-historyWindow), 60)
		if err != nil {
			log.Printf("international network history unavailable: %v", err)
		}
		service.domesticHistory, err = repository.RecentNetworkSamples(domesticGroup, time.Now().Add(-historyWindow), 60)
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
	copy.History = recentCopy(s.history)
	copy.International = groupHealth(copy, copy.History)
	if s.current.Domestic != nil {
		domestic := *s.current.Domestic
		domestic.Targets = append([]string(nil), domestic.Targets...)
		domestic.History = recentCopy(s.domesticHistory)
		copy.Domestic = &domestic
	}
	return &copy
}

func recentCopy(history []model.NetworkSample) []model.NetworkSample {
	result := make([]model.NetworkSample, 0, len(history))
	cutoff := time.Now().Add(-historyWindow)
	for _, sample := range history {
		if sample.CheckedAt.Before(cutoff) {
			continue
		}
		item := sample
		item.Targets = append([]string(nil), sample.Targets...)
		result = append(result, item)
	}
	return result
}

func groupHealth(health model.NetworkHealth, history []model.NetworkSample) *model.NetworkGroupHealth {
	return &model.NetworkGroupHealth{
		Status: health.Status, LatencyMS: health.LatencyMS,
		PacketLossPct: health.PacketLossPct, PacketsSent: health.PacketsSent,
		PacketsReceived: health.PacketsReceived, Targets: append([]string(nil), health.Targets...),
		CheckedAt: health.CheckedAt, Error: health.Error, History: history,
	}
}

func (s *Service) Run(ctx context.Context) {
	for ctx.Err() == nil {
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

		timer := time.NewTimer(refreshInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Service) measureGroup(ctx context.Context, targets []net.IP, labels []string, setupErr error, domestic bool) model.NetworkHealth {
	if setupErr != nil {
		return model.NetworkHealth{Status: "error", Error: setupErr.Error(), CheckedAt: time.Now().UTC()}
	}
	if s.demo {
		if domestic {
			return model.NetworkHealth{Status: "ok", LatencyMS: 162.4, PacketLossPct: 0, PacketsSent: 10, PacketsReceived: 10, CheckedAt: time.Now().UTC(), Targets: append([]string(nil), labels...)}
		}
		return model.NetworkHealth{Status: "ok", LatencyMS: 41.8, PacketLossPct: 10, PacketsSent: 10, PacketsReceived: 9, CheckedAt: time.Now().UTC(), Targets: append([]string(nil), labels...)}
	}
	return measure(ctx, targets, labels, s.probe)
}

func appendRecent(history []model.NetworkSample, sample model.NetworkSample) []model.NetworkSample {
	history = append(history, sample)
	cutoff := sample.CheckedAt.Add(-historyWindow)
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
		Targets:         append([]string(nil), health.Targets...), CheckedAt: health.CheckedAt,
	}
}

func demoHistory(now time.Time, targets []string, domestic bool) []model.NetworkSample {
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
		result = append(result, model.NetworkSample{
			Status: "ok", LatencyMS: latency, PacketLossPct: loss,
			PacketsSent: 10, PacketsReceived: 10 - int(loss/10),
			Targets: append([]string(nil), targets...), CheckedAt: now.Add(-time.Duration(minute) * time.Minute),
		})
	}
	return result
}

func measure(ctx context.Context, targets []net.IP, labels []string, probe targetProbe) (health model.NetworkHealth) {
	health = model.NetworkHealth{Status: "error", Targets: append([]string(nil), labels...)}
	defer func() { health.CheckedAt = time.Now().UTC() }()
	if len(targets) == 0 {
		health.Error = "没有可用的探测目标"
		return health
	}
	results := make(chan targetResult, len(targets))
	for _, target := range targets {
		go func(ip net.IP) { results <- probe(ctx, ip) }(target)
	}
	var roundTrips []time.Duration
	var failures []string
	for range targets {
		result := <-results
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
	var result targetResult
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		result.err = fmt.Errorf("%s: 无法打开 ICMP socket: %w", target, err)
		return result
	}
	defer conn.Close()
	var token [8]byte
	if _, err = rand.Read(token[:]); err != nil {
		result.err = err
		return result
	}
	id := int(binary.BigEndian.Uint16(token[:2]))
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
		if _, err = conn.WriteTo(packet, &net.IPAddr{IP: target}); err != nil {
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
			address, ok := sender.(*net.IPAddr)
			if !ok || !address.IP.Equal(target) {
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
