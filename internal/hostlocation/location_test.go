package hostlocation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func TestParseTrace(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"IPv4", "ip=1.1.1.1\nloc=US\n", true},
		{"IPv6", "ip=2606:4700:4700::1111\nloc=de\n", true},
		{"private", "ip=192.168.1.1\nloc=US\n", false},
		{"unknown", "ip=1.1.1.1\nloc=XX\n", false},
		{"missing", "ip=1.1.1.1\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			location, err := parseTrace(strings.NewReader(tc.body))
			if (err == nil) != tc.ok {
				t.Fatalf("location=%+v, err=%v", location, err)
			}
			if tc.name == "IPv6" && location.CountryCode != "DE" {
				t.Fatalf("country code=%q", location.CountryCode)
			}
		})
	}
}

func TestParseTraceIPAndPlain(t *testing.T) {
	ip, country, err := parseTraceIP(strings.NewReader("ip=1.1.1.1\nloc=T1\n"))
	if err != nil || ip != "1.1.1.1" || country != "T1" {
		t.Fatalf("unexpected parseTraceIP: ip=%s, country=%s, err=%v", ip, country, err)
	}

	plain, err := parsePlainIP(" 2606:4700:4700::1111 \n")
	if err != nil || plain != "2606:4700:4700::1111" {
		t.Fatalf("unexpected parsePlainIP: plain=%s, err=%v", plain, err)
	}

	_, err = parsePlainIP("10.0.0.1")
	if err == nil {
		t.Fatal("expected error for private IP in parsePlainIP")
	}
}

func TestMergeBindAddresses(t *testing.T) {
	a := []model.BindAddress{
		{Address: "1.1.1.1", Interface: "eth0"},
		{Address: "2600::1", Interface: "eth0"},
	}
	b := []model.BindAddress{
		{Address: "1.1.1.1", Interface: "eth0"},
		{Address: "2600::2", Interface: "eth0"},
		{Address: "2600::3", Interface: "wg0"},
	}
	merged := MergeBindAddresses(a, b)
	if len(merged) != 4 {
		t.Fatalf("expected 4 merged addresses, got %d: %+v", len(merged), merged)
	}
}

func TestDetectorCachesLastGoodLocation(t *testing.T) {
	response := "ip=1.1.1.1\nloc=US\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()
	detector := New()
	detector.endpoint = server.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go detector.Run(ctx)
	deadline := time.After(time.Second)
	for detector.Current() == nil {
		select {
		case <-deadline:
			t.Fatal("location was not detected")
		case <-time.After(time.Millisecond):
		}
	}
	copy := detector.Current()
	copy.CountryCode = "ZZ"
	if detector.Current().CountryCode != "US" {
		t.Fatal("Current returned mutable internal state")
	}
}
