// Package iplocation provides bounded, asynchronous country lookup for public IPs.
package iplocation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Location struct {
	IP          string `json:"ip"`
	CountryCode string `json:"countryCode,omitempty"`
	Status      string `json:"status"` // pending, ready, private, unavailable
}
type entry struct {
	location Location
	expires  time.Time
}
type Resolver struct {
	mu       sync.Mutex
	cache    map[string]entry
	client   *http.Client
	endpoint string
	interval time.Duration
	next     time.Time
	pending  int
}

func New() *Resolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Resolver{cache: make(map[string]entry), endpoint: "https://ipwho.is/", interval: time.Second,
		client: &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
}

func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, block := range reserved {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

// Lookup returns immediately. The next UI poll receives the cached result;
// neither security sampling nor HTTP handlers wait for the external provider.
func (r *Resolver) Lookup(raw string) (Location, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return Location{}, errors.New("invalid IP address")
	}
	ip = ip.Unmap()
	key := ip.String()
	if !Public(ip) {
		return Location{IP: key, Status: "private"}, nil
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if cached, ok := r.cache[key]; ok && now.Before(cached.expires) {
		return cached.location, nil
	}
	if r.pending >= 64 {
		return Location{IP: key, Status: "unavailable"}, nil
	}
	if len(r.cache) >= 1024 {
		oldestKey := ""
		var oldest time.Time
		for candidate, value := range r.cache {
			if value.location.Status == "pending" {
				continue
			}
			if oldestKey == "" || value.expires.Before(oldest) {
				oldestKey, oldest = candidate, value.expires
			}
		}
		if oldestKey != "" {
			delete(r.cache, oldestKey)
		}
	}
	start := now
	if r.next.After(start) {
		start = r.next
	}
	r.next = start.Add(r.interval)
	location := Location{IP: key, Status: "pending"}
	r.cache[key] = entry{location, start.Add(time.Minute)}
	r.pending++
	go r.resolve(ip, time.Until(start))
	return location, nil
}

func (r *Resolver) resolve(ip netip.Addr, delay time.Duration) {
	if delay > 0 {
		timer := time.NewTimer(delay)
		<-timer.C
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	location := Location{IP: ip.String(), Status: "unavailable"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint+ip.String()+"?fields=ip,success,country_code", nil)
	if err == nil {
		response, e := r.client.Do(req)
		if e == nil {
			defer response.Body.Close()
			var data struct {
				Success     bool   `json:"success"`
				IP          string `json:"ip"`
				CountryCode string `json:"country_code"`
			}
			if response.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&data) == nil && data.Success {
				returned, e := netip.ParseAddr(data.IP)
				code := strings.ToUpper(data.CountryCode)
				if e == nil && returned.Unmap() == ip && len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' && code != "XX" && code != "ZZ" {
					location.CountryCode, location.Status = code, "ready"
				}
			}
		}
	}
	ttl := 5 * time.Minute
	if location.Status == "ready" {
		ttl = 24 * time.Hour
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[ip.String()] = entry{location, time.Now().Add(ttl)}
	r.pending--
}
