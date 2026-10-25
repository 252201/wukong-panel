package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/store"
)

func TestLatestRelease_Success(t *testing.T) {
	server, _ := fleetWebTestServer(t)

	// Reset cache before test
	globalReleaseCache.mu.Lock()
	globalReleaseCache.fetchedAt = time.Time{}
	globalReleaseCache.result = latestReleaseResult{}
	globalReleaseCache.mu.Unlock()

	mockRelease := `{
		"tag_name": "v1.7.26",
		"name": "v1.7.26",
		"published_at": "2026-10-24T16:24:31Z",
		"html_url": "https://github.com/252201/wukong-panel/releases/tag/v1.7.26",
		"body": "Test release notes"
	}`

	mockSingBoxRelease := `{
		"tag_name": "v1.14.4",
		"name": "v1.14.4",
		"published_at": "2026-10-25T00:00:00Z",
		"html_url": "https://github.com/SagerNet/sing-box/releases/tag/v1.14.4"
	}`

	server.fleetProbeClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			if strings.Contains(req.URL.Path, "SagerNet/sing-box") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(mockSingBoxRelease)),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
				}
			}
			if strings.Contains(req.URL.Path, "/releases/latest") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(mockRelease)),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
				}
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
				Header:     make(http.Header),
			}
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/latest-release", nil)
	server.latestRelease(w, r, store.Session{})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var data latestReleaseResult
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	if !data.OK {
		t.Fatalf("expected ok=true, got %v", data.OK)
	}
	if data.Version != "1.7.26" {
		t.Fatalf("expected version 1.7.26, got %s", data.Version)
	}
	if data.Tag != "v1.7.26" {
		t.Fatalf("expected tag v1.7.26, got %s", data.Tag)
	}
	if data.Body != "Test release notes" {
		t.Fatalf("expected body 'Test release notes', got %s", data.Body)
	}
	if data.SingBoxVersion != "1.14.4" {
		t.Fatalf("expected singBoxVersion 1.14.4, got %s", data.SingBoxVersion)
	}
}

func TestLatestRelease_Fallback(t *testing.T) {
	server, _ := fleetWebTestServer(t)

	// Reset cache before test
	globalReleaseCache.mu.Lock()
	globalReleaseCache.fetchedAt = time.Time{}
	globalReleaseCache.result = latestReleaseResult{}
	globalReleaseCache.mu.Unlock()

	// Simulate GitHub error
	server.fleetProbeClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(strings.NewReader(`{"message":"bad gateway"}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/latest-release", nil)
	server.latestRelease(w, r, store.Session{})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 fallback, got %d: %s", w.Code, w.Body.String())
	}

	var data latestReleaseResult
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	if !data.OK {
		t.Fatalf("expected ok=true, got %v", data.OK)
	}
	if data.Version == "" {
		t.Fatalf("expected non-empty fallback version")
	}
	if data.SingBoxVersion != "1.14.4" {
		t.Fatalf("expected fallback singBoxVersion 1.14.4, got %s", data.SingBoxVersion)
	}
}
