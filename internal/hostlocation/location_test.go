package hostlocation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
