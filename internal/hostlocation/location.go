package hostlocation

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

const (
	traceURL     = "https://www.cloudflare.com/cdn-cgi/trace"
	traceIPv4URL = "https://1.1.1.1/cdn-cgi/trace"
	traceIPv6URL = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
)

var (
	v4ProbeEndpoints = []string{
		"https://www.cloudflare.com/cdn-cgi/trace",
		traceIPv4URL,
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.ident.me",
	}
	v6ProbeEndpoints = []string{
		"https://www.cloudflare.com/cdn-cgi/trace",
		traceIPv6URL,
		"https://api64.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.ident.me",
	}
)

// Detector observes the host's direct public egress IP without delaying fleet requests.
type Detector struct {
	client   *http.Client
	endpoint string
	mu       sync.RWMutex
	current  *model.HostLocation
}

func New() *Detector {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // The location must describe this host, not an HTTP proxy.
	return &Detector{
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		endpoint: traceURL,
	}
}

func (d *Detector) Current() *model.HostLocation {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.current == nil {
		return nil
	}
	copy := *d.current
	return &copy
}

func (d *Detector) Run(ctx context.Context) {
	for ctx.Err() == nil {
		interval := 10 * time.Minute
		if location, err := d.lookup(ctx); err == nil {
			d.mu.Lock()
			d.current = location
			d.mu.Unlock()
			if location.IPv4 != "" && location.IPv6 != "" {
				interval = 2 * time.Hour
			} else {
				interval = 15 * time.Minute
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (d *Detector) lookup(ctx context.Context) (*model.HostLocation, error) {
	// If a custom endpoint was configured (e.g. in unit tests), prioritize it.
	if d.endpoint != traceURL {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.endpoint, nil)
		if err != nil {
			return nil, err
		}
		response, err := d.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("location trace returned HTTP %d", response.StatusCode)
		}
		return parseTrace(io.LimitReader(response.Body, 4096))
	}

	loc := &model.HostLocation{}

	// Primary egress probe via standard trace endpoint
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.endpoint, nil); err == nil {
		if resp, err := d.client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if parsed, err := parseTrace(io.LimitReader(resp.Body, 4096)); err == nil {
					loc = parsed
				}
			}
		}
	}

	// Active dual-stack probing with forced TCP family transports and multiple fallbacks
	if loc.IPv4 == "" {
		if ip4, c4, err := probeFamily(ctx, "tcp4", v4ProbeEndpoints); err == nil && ip4 != "" {
			loc.IPv4 = ip4
			if loc.CountryCode == "" && c4 != "" {
				loc.CountryCode = c4
			}
		}
	}

	if loc.IPv6 == "" {
		if ip6, c6, err := probeFamily(ctx, "tcp6", v6ProbeEndpoints); err == nil && ip6 != "" {
			loc.IPv6 = ip6
			if loc.CountryCode == "" && c6 != "" {
				loc.CountryCode = c6
			}
		}
	}

	if loc.PublicIP == "" {
		if loc.IPv4 != "" {
			loc.PublicIP = loc.IPv4
		} else if loc.IPv6 != "" {
			loc.PublicIP = loc.IPv6
		}
	}

	if loc.PublicIP == "" && loc.IPv4 == "" && loc.IPv6 == "" {
		return nil, errors.New("location trace did not detect any public IP")
	}

	return loc, nil
}

func probeFamily(ctx context.Context, network string, endpoints []string) (string, string, error) {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, _, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(dialCtx, network, addr)
		},
		ResponseHeaderTimeout: 3 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   4 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var lastErr error
	for _, endpoint := range endpoints {
		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("endpoint %s returned HTTP %d", endpoint, resp.StatusCode)
			continue
		}

		if strings.Contains(endpoint, "cdn-cgi/trace") {
			ip, country, err := parseTraceIP(strings.NewReader(string(body)))
			if err == nil && ip != "" {
				return ip, country, nil
			}
			lastErr = err
		} else {
			ip, err := parsePlainIP(string(body))
			if err == nil && ip != "" {
				return ip, "", nil
			}
			lastErr = err
		}
	}

	if lastErr != nil {
		return "", "", lastErr
	}
	return "", "", errors.New("no endpoint succeeded")
}

func parseTraceIP(reader io.Reader) (string, string, error) {
	scanner := bufio.NewScanner(reader)
	var rawIP, country string
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "ip":
			rawIP = strings.TrimSpace(value)
		case "loc":
			country = strings.ToUpper(strings.TrimSpace(value))
		}
	}
	if rawIP == "" {
		return "", "", errors.New("trace missing ip")
	}
	ip, err := netip.ParseAddr(rawIP)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", "", errors.New("invalid public IP in trace")
	}
	return rawIP, country, nil
}

func parsePlainIP(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", errors.New("invalid plain public IP")
	}
	return raw, nil
}

func parseTrace(reader io.Reader) (*model.HostLocation, error) {
	var location model.HostLocation
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "ip":
			location.PublicIP = strings.TrimSpace(value)
		case "loc":
			location.CountryCode = strings.ToUpper(strings.TrimSpace(value))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(location.PublicIP)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return nil, errors.New("location trace did not contain a public IP")
	}
	if ip.Is4() {
		location.IPv4 = location.PublicIP
	} else if ip.Is6() {
		location.IPv6 = location.PublicIP
	}
	code := location.CountryCode
	if len(code) != 2 || code == "XX" || code == "T1" || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return nil, errors.New("location trace did not contain a valid country")
	}
	return &location, nil
}

// GetInterfaceAddresses scans all active, non-loopback network interfaces for public IP addresses.
// It includes physical interfaces as well as virtual and tunnel interfaces (e.g. wg, warp, tun).
func GetInterfaceAddresses() (v4, v6 []model.BindAddress) {
	v4 = make([]model.BindAddress, 0)
	v6 = make([]model.BindAddress, 0)
	interfaces, err := net.Interfaces()
	if err != nil {
		return v4, v6
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipStr := strings.Split(addr.String(), "/")[0]
			ip, err := netip.ParseAddr(ipStr)
			if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.Is4() {
				// Filter Carrier-Grade NAT (100.64.0.0/10)
				b := ip.As4()
				if b[0] == 100 && (b[1]&0xc0) == 64 {
					continue
				}
				v4 = append(v4, model.BindAddress{
					Address:   ipStr,
					Interface: iface.Name,
				})
			} else if ip.Is6() {
				// Filter Unique Local Addresses (fc00::/7)
				b := ip.As16()
				if (b[0] & 0xfe) == 0xfc {
					continue
				}
				v6 = append(v6, model.BindAddress{
					Address:   ipStr,
					Interface: iface.Name,
				})
			}
		}
	}
	return UniqueBindAddresses(v4), UniqueBindAddresses(v6)
}

func UniqueBindAddresses(in []model.BindAddress) []model.BindAddress {
	out := make([]model.BindAddress, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, item := range in {
		key := item.Interface + "\x00" + item.Address
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

// MergeBindAddresses combines two BindAddress slices, deduplicating by address string.
func MergeBindAddresses(primary, secondary []model.BindAddress) []model.BindAddress {
	out := make([]model.BindAddress, 0, len(primary)+len(secondary))
	seen := make(map[string]bool)
	for _, item := range primary {
		addr := strings.TrimSpace(item.Address)
		if addr != "" && !seen[addr] {
			seen[addr] = true
			out = append(out, item)
		}
	}
	for _, item := range secondary {
		addr := strings.TrimSpace(item.Address)
		if addr != "" && !seen[addr] {
			seen[addr] = true
			out = append(out, item)
		}
	}
	return out
}
