package iplocation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitResult(t *testing.T, r *Resolver, ip string) Location {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		result, err := r.Lookup(ip)
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "pending" {
			return result
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("country lookup did not finish")
	return Location{}
}
func TestLookupAsyncDeduplicatedCachedAndDoesNotQueryPrivateIPs(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
		fmt.Fprint(w, `{"success":true,"ip":"8.8.8.8","country_code":"US"}`)
	}))
	defer srv.Close()
	r := New()
	r.endpoint = srv.URL + "/"
	r.interval = 0
	start := time.Now()
	value, err := r.Lookup("::ffff:8.8.8.8")
	if err != nil || value.Status != "pending" || time.Since(start) > 100*time.Millisecond {
		t.Fatal("lookup blocked", value, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.Lookup("8.8.8.8") }()
	}
	wg.Wait()
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "fc00::1", "169.254.1.1", "100.64.0.1", "203.0.113.1", "2001:db8::1", "0.0.0.0", "224.0.0.1"} {
		value, err = r.Lookup(ip)
		if err != nil || value.Status != "private" {
			t.Fatalf("private %s %+v %v", ip, value, err)
		}
	}
	for _, ip := range []string{"https://localhost/", "8.8.8.8/24", "8.8.8.8?x=y", "fe80::1%eth0"} {
		if _, err = r.Lookup(ip); err == nil {
			t.Fatalf("invalid IP %s accepted", ip)
		}
	}
	close(release)
	value = waitResult(t, r, "8.8.8.8")
	if value.Status != "ready" || value.CountryCode != "US" || calls.Load() != 1 {
		t.Fatalf("%+v calls %d", value, calls.Load())
	}
	r.Lookup("8.8.8.8")
	if calls.Load() != 1 {
		t.Fatal("cache ignored")
	}
}
func TestLookupUnavailableOnBadCountryMismatchedIPAndRedirect(t *testing.T) {
	for _, body := range []string{`{"success":false}`, `{"success":true,"ip":"1.1.1.1","country_code":"US"}`, `{"success":true,"ip":"8.8.8.8","country_code":"<script>"}`, strings.Repeat("x", 5000)} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		r := New()
		r.endpoint = srv.URL + "/"
		r.interval = 0
		value := waitResult(t, r, "8.8.8.8")
		if value.Status != "unavailable" || value.CountryCode != "" {
			t.Fatalf("bad response: %+v", value)
		}
		srv.Close()
	}
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer srv.Close()
	r := New()
	r.endpoint = srv.URL + "/"
	r.interval = 0
	if value := waitResult(t, r, "8.8.8.8"); value.Status != "unavailable" || redirected.Load() != 0 {
		t.Fatalf("redirect followed: %+v", value)
	}
}
func TestLookupIPv6AndAdmissionLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"ip":"2001:4860:4860::8888","country_code":"US"}`)
	}))
	defer srv.Close()
	r := New()
	r.endpoint = srv.URL + "/"
	r.interval = 0
	if value := waitResult(t, r, "2001:4860:4860::8888"); value.Status != "ready" {
		t.Fatalf("%+v", value)
	}
	r.mu.Lock()
	r.pending = 64
	r.mu.Unlock()
	if value, _ := r.Lookup("1.1.1.1"); value.Status != "unavailable" {
		t.Fatal("admission limit ignored")
	}
}
