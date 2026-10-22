package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/store"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestIPReputation_Validation(t *testing.T) {
	server, _ := fleetWebTestServer(t)

	// Missing IP
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/ip-reputation", nil)
	server.ipReputation(w, r, store.Session{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing IP, got %d", w.Code)
	}

	// Invalid IP
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/api/v1/system/ip-reputation?ip=not-an-ip", nil)
	server.ipReputation(w, r, store.Session{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid IP, got %d", w.Code)
	}
}

func TestIPReputation_Success(t *testing.T) {
	server, _ := fleetWebTestServer(t)

	mockBody := `{"ip":"1.1.1.1","trust_score":95,"is_datacenter":true}`
	server.fleetProbeClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			if !strings.Contains(req.URL.Path, "1.1.1.1") {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(mockBody)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/ip-reputation?ip=1.1.1.1", nil)
	server.ipReputation(w, r, store.Session{})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if data["ip"] != "1.1.1.1" {
		t.Fatalf("expected ip 1.1.1.1, got %v", data["ip"])
	}
	if data["trust_score"] != float64(95) {
		t.Fatalf("expected trust_score 95, got %v", data["trust_score"])
	}
}
