package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Minimal Hub scaffold: host registry + browser-facing host list.
// Full browser↔host relay (WebSocket) lands in a follow-up iteration.
// Local multi-host is not required for single-machine acp-fe → acp-host.

type HostInfo struct {
	HostID    string    `json:"hostId"`
	HostName  string    `json:"hostName"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"lastSeen"`
	Meta      map[string]any `json:"meta,omitempty"`
}

type Registry struct {
	mu    sync.RWMutex
	hosts map[string]*HostInfo
}

func NewRegistry() *Registry {
	return &Registry{hosts: make(map[string]*HostInfo)}
}

func (r *Registry) Upsert(h HostInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h.Online = true
	h.LastSeen = time.Now()
	r.hosts[h.HostID] = &h
}

func (r *Registry) List() []HostInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]HostInfo, 0, len(r.hosts))
	for _, h := range r.hosts {
		cp := *h
		// mark stale offline
		if time.Since(cp.LastSeen) > 60*time.Second {
			cp.Online = false
		}
		out = append(out, cp)
	}
	return out
}

func main() {
	port := 8787
	if v := os.Getenv("PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	}
	reg := NewRegistry()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "acp-hub"})
	})

	mux.HandleFunc("GET /api/hosts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"hosts": reg.List()})
	})

	// Host self-register (HTTP heartbeat for now; WS later)
	mux.HandleFunc("POST /api/host/register", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			HostID   string         `json:"hostId"`
			HostName string         `json:"hostName"`
			Token    string         `json:"token"`
			Meta     map[string]any `json:"meta"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.HostID == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "invalid body"})
			return
		}
		// TODO: verify Token against HUB_TOKEN
		reg.Upsert(HostInfo{
			HostID:   body.HostID,
			HostName: body.HostName,
			Meta:     body.Meta,
		})
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	// Placeholder: browser will later open WS at /ws/browser
	mux.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"service": "acp-hub",
			"version": "0.1.0-scaffold",
			"modes":   []string{"register", "list-hosts"},
			"todo":    []string{"websocket relay", "auth", "session routing"},
		})
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("[acp-hub] listening on http://localhost:%d (scaffold)", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
