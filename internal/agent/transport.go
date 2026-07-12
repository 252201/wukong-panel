package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/singboxconfig"
)

type Server struct {
	manager *Manager
	token   string
}

func NewServer(manager *Manager, token string) *Server {
	return &Server{manager: manager, token: token}
}

func (s *Server) ListenAndServe(ctx context.Context, socket string) error {
	if s.token == "" {
		return errors.New("agent token is required")
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
		return err
	}
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0o660); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.manager.Version(r.Context())})
	}))
	mux.HandleFunc("GET /scan", s.authorize(s.scan))
	mux.HandleFunc("POST /import", s.authorize(s.importNodes))
	mux.HandleFunc("POST /nodes", s.authorize(s.create))
	mux.HandleFunc("POST /nodes/{id}/action", s.authorize(s.action))
	mux.HandleFunc("GET /nodes/{id}/share", s.authorize(s.share))
	mux.HandleFunc("GET /sing-box/migration-plan", s.authorize(s.migrationPlan))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	return server.Serve(listener)
}

func (s *Server) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Wukong-Agent-Token") != s.token {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	items, err := s.manager.Scan(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	for i := range items {
		items[i].Secret = ""
	}
	writeJSON(w, 200, items)
}
func (s *Server) importNodes(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Fingerprints []string `json:"fingerprints"`
	}
	if !decode(w, r, &request) {
		return
	}
	count, err := s.manager.Import(r.Context(), request.Fingerprints)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"imported": count})
}
func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var request model.NodeCreateRequest
	if !decode(w, r, &request) {
		return
	}
	node, err := s.manager.Create(r.Context(), request)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, node)
}
func (s *Server) action(w http.ResponseWriter, r *http.Request) {
	var request model.NodeActionRequest
	if !decode(w, r, &request) {
		return
	}
	if err := s.manager.Action(r.Context(), r.PathValue("id"), request.Action, request.ConfirmName); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	share, err := s.manager.Share(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, share)
}
func (s *Server) migrationPlan(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "1.13.14"
	}
	plan, err := s.manager.MigrationPlan(r.Context(), target)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, plan)
}

type Client struct {
	http  *http.Client
	token string
}

func NewClient(socket, token string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 60 * time.Second}, token: token}
}
func (c *Client) request(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("X-Wukong-Agent-Token", c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
		return fmt.Errorf("agent: %s", strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.NewDecoder(response.Body).Decode(out)
	}
	return nil
}
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	err := c.request(ctx, "GET", "/health", nil, &result)
	return result, err
}
func (c *Client) Scan(ctx context.Context) ([]model.NodeCandidate, error) {
	var result []model.NodeCandidate
	err := c.request(ctx, "GET", "/scan", nil, &result)
	return result, err
}
func (c *Client) Import(ctx context.Context, ids []string) error {
	return c.request(ctx, "POST", "/import", map[string]any{"fingerprints": ids}, nil)
}
func (c *Client) Create(ctx context.Context, request model.NodeCreateRequest) (model.Node, error) {
	var node model.Node
	err := c.request(ctx, "POST", "/nodes", request, &node)
	return node, err
}
func (c *Client) Action(ctx context.Context, id string, request model.NodeActionRequest) error {
	return c.request(ctx, "POST", "/nodes/"+id+"/action", request, nil)
}
func (c *Client) Share(ctx context.Context, id string) (model.Share, error) {
	var share model.Share
	err := c.request(ctx, "GET", "/nodes/"+id+"/share", nil, &share)
	return share, err
}
func (c *Client) MigrationPlan(ctx context.Context, target string) (singboxconfig.Plan, error) {
	var plan singboxconfig.Plan
	err := c.request(ctx, "GET", "/sing-box/migration-plan?target="+url.QueryEscape(target), nil, &plan)
	return plan, err
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, 400, "invalid request: "+err.Error())
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
