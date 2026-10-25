package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/252201/wukong-panel/internal/store"
)

type githubReleasePayload struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
}

type latestReleaseResult struct {
	OK          bool   `json:"ok"`
	Version     string `json:"version"`
	Tag         string `json:"tag"`
	Name        string `json:"name"`
	PublishedAt string `json:"publishedAt,omitempty"`
	HTMLURL     string `json:"htmlUrl,omitempty"`
	Body        string `json:"body,omitempty"`
}

type releaseCache struct {
	mu        sync.Mutex
	fetchedAt time.Time
	result    latestReleaseResult
}

var globalReleaseCache releaseCache

func (s *Server) latestRelease(w http.ResponseWriter, r *http.Request, _ store.Session) {
	globalReleaseCache.mu.Lock()
	if !globalReleaseCache.fetchedAt.IsZero() && time.Since(globalReleaseCache.fetchedAt) < 15*time.Minute && globalReleaseCache.result.OK {
		res := globalReleaseCache.result
		globalReleaseCache.mu.Unlock()
		writeJSON(w, http.StatusOK, res)
		return
	}
	globalReleaseCache.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/252201/wukong-panel/releases/latest", nil)
	if err != nil {
		s.respondWithFallbackRelease(w)
		return
	}
	req.Header.Set("User-Agent", "Wukong-Panel/"+s.version)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := s.fleetProbeClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		s.respondWithFallbackRelease(w)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		s.respondWithFallbackRelease(w)
		return
	}

	var gh githubReleasePayload
	if err := json.Unmarshal(body, &gh); err != nil || gh.TagName == "" {
		s.respondWithFallbackRelease(w)
		return
	}

	cleanVer := strings.TrimPrefix(gh.TagName, "v")
	res := latestReleaseResult{
		OK:          true,
		Version:     cleanVer,
		Tag:         gh.TagName,
		Name:        gh.Name,
		PublishedAt: gh.PublishedAt,
		HTMLURL:     gh.HTMLURL,
		Body:        gh.Body,
	}

	globalReleaseCache.mu.Lock()
	globalReleaseCache.fetchedAt = time.Now()
	globalReleaseCache.result = res
	globalReleaseCache.mu.Unlock()

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) respondWithFallbackRelease(w http.ResponseWriter) {
	globalReleaseCache.mu.Lock()
	if globalReleaseCache.result.OK {
		cached := globalReleaseCache.result
		globalReleaseCache.mu.Unlock()
		writeJSON(w, http.StatusOK, cached)
		return
	}
	globalReleaseCache.mu.Unlock()

	cleanVer := strings.TrimPrefix(s.version, "v")
	if cleanVer == "" || cleanVer == "dev" {
		cleanVer = "1.7.26"
	}
	fallback := latestReleaseResult{
		OK:      true,
		Version: cleanVer,
		Tag:     "v" + cleanVer,
		Name:    "v" + cleanVer,
		HTMLURL: fmt.Sprintf("https://github.com/252201/wukong-panel/releases/tag/v%s", cleanVer),
	}
	writeJSON(w, http.StatusOK, fallback)
}
