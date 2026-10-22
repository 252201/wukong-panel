package hostlocation

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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
		interval := 15 * time.Minute
		if location, err := d.lookup(ctx); err == nil {
			d.mu.Lock()
			d.current = location
			d.mu.Unlock()
			interval = 6 * time.Hour
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
	loc, err := parseTrace(io.LimitReader(response.Body, 4096))
	if err != nil {
		return nil, err
	}

	// If using the standard trace endpoint, probe the opposite address family to capture both IPv4 and IPv6
	if d.endpoint == traceURL {
		if loc.IPv4 == "" {
			if v4, err := d.probeSingle(ctx, traceIPv4URL); err == nil && v4.IPv4 != "" {
				loc.IPv4 = v4.IPv4
			}
		}
		if loc.IPv6 == "" {
			if v6, err := d.probeSingle(ctx, traceIPv6URL); err == nil && v6.IPv6 != "" {
				loc.IPv6 = v6.IPv6
			}
		}
	}

	return loc, nil
}

func (d *Detector) probeSingle(ctx context.Context, endpoint string) (*model.HostLocation, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseTrace(io.LimitReader(resp.Body, 4096))
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
