package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/8w6s/noxis/internal/blocklist"
	"github.com/8w6s/noxis/internal/defense"
)

// Server provides a local API for the NoxCtl CLI to manage the engine
type Server struct {
	port          string
	blManager     *blocklist.Manager
	wafEnabled    *atomic.Bool
	defenseManager *defense.Manager
	resyncFn      func() // optional: triggers shield reconciliation
}

// New creates a new admin API server
func New(port string, blManager *blocklist.Manager) *Server {
	wafEnabled := &atomic.Bool{}
	wafEnabled.Store(true)
	return &Server{
		port:       port,
		blManager:  blManager,
		wafEnabled: wafEnabled,
	}
}

// WithDefenseManager injects the defense manager for mode control via API
func (s *Server) WithDefenseManager(dm *defense.Manager) *Server {
	s.defenseManager = dm
	return s
}

// WithResyncFn injects a callback that triggers shield reconciliation
func (s *Server) WithResyncFn(fn func()) *Server {
	s.resyncFn = fn
	return s
}

// GetWAFEnabled returns the shared WAF toggle so other modules can check it
func (s *Server) GetWAFEnabled() *atomic.Bool {
	return s.wafEnabled
}

// Start boots up the admin HTTP server on the localhost interface.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Basic CORS for the dashboard (running on same host but different port)
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
			h(w, r)
		}
	}

	// --- IP Management ---
	mux.HandleFunc("/api/block", wrap(s.handleBlock))
	mux.HandleFunc("/api/unblock", wrap(s.handleUnblock))
	mux.HandleFunc("/api/whitelist", wrap(s.handleWhitelist))
	mux.HandleFunc("/api/list", wrap(s.handleList))
	mux.HandleFunc("/api/clear-all", wrap(s.handleClearAll))

	// --- WAF Control ---
	mux.HandleFunc("/api/waf/status", wrap(s.handleWAFStatus))
	mux.HandleFunc("/api/waf/toggle", wrap(s.handleWAFToggle))

	// --- Defense Mode Control ---
	mux.HandleFunc("/api/mode", wrap(s.handleSetMode))
	mux.HandleFunc("/api/resync", wrap(s.handleResync))

	// --- Engine Status ---
	mux.HandleFunc("/api/status", wrap(s.handleStatus))

	log.Printf("[Admin] API Server listening on %s", s.port)
	return http.ListenAndServe(s.port, mux)
}

// ============================================================
// IP Management Handlers
// ============================================================

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	reason := r.URL.Query().Get("reason")
	if ip == "" {
		http.Error(w, "Missing 'ip' query parameter", http.StatusBadRequest)
		return
	}
	if reason == "" {
		reason = "manual_dashboard"
	}

	err := s.blManager.Block(r.Context(), ip, reason)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to block IP: %v", err), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"status": "blocked", "ip": ip})
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "Missing 'ip' query parameter", http.StatusBadRequest)
		return
	}

	err := s.blManager.Unblock(r.Context(), ip)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to unblock IP: %v", err), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"status": "unblocked", "ip": ip})
}

func (s *Server) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "Missing 'ip' query parameter", http.StatusBadRequest)
		return
	}

	err := s.blManager.Whitelist(r.Context(), ip)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to whitelist IP: %v", err), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"status": "whitelisted", "ip": ip})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ips, err := s.blManager.List(context.Background())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch blocked IPs: %v", err), http.StatusInternalServerError)
		return
	}

	if ips == nil {
		ips = []blocklist.BlockedIP{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ips)
}

func (s *Server) handleClearAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ips, err := s.blManager.List(context.Background())
	if err != nil {
		http.Error(w, "Failed to list IPs for clearing", http.StatusInternalServerError)
		return
	}

	count := 0
	for _, entry := range ips {
		s.blManager.Unblock(context.Background(), entry.IP)
		count++
	}

	jsonOK(w, map[string]interface{}{"status": "cleared", "count": count})
}

// handleSetMode allows operator to manually change the defense mode
func (s *Server) handleSetMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		http.Error(w, "Missing 'mode' query parameter", http.StatusBadRequest)
		return
	}

	if s.defenseManager == nil {
		http.Error(w, "Defense manager not configured", http.StatusNotImplemented)
		return
	}

	var dm defense.Mode
	switch mode {
	case "normal":
		dm = defense.ModeNormal
	case "elevated":
		dm = defense.ModeElevated
	case "under_attack":
		dm = defense.ModeUnderAttack
	case "recovery":
		dm = defense.ModeRecovery
	default:
		http.Error(w, fmt.Sprintf("Unknown mode: %s", mode), http.StatusBadRequest)
		return
	}

	s.defenseManager.SetMode(dm, "manual_dashboard")
	log.Printf("[Admin] Defense mode manually set to '%s' via Dashboard API", mode)
	jsonOK(w, map[string]string{"status": "ok", "mode": mode})
}

// handleResync triggers a manual shield reconciliation
func (s *Server) handleResync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.resyncFn != nil {
		go s.resyncFn()
		log.Printf("[Admin] Shield resync triggered via Dashboard API")
		jsonOK(w, map[string]string{"status": "resync_queued"})
		return
	}
	jsonOK(w, map[string]string{"status": "no_resync_configured"})
}


func (s *Server) handleWAFStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, map[string]interface{}{"enabled": s.wafEnabled.Load()})
}

func (s *Server) handleWAFToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	current := s.wafEnabled.Load()
	s.wafEnabled.Store(!current)
	state := "enabled"
	if current {
		state = "disabled"
	}
	log.Printf("[Admin] WAF %s via Dashboard API", state)
	jsonOK(w, map[string]interface{}{"enabled": !current, "message": "WAF " + state})
}

// ============================================================
// Engine Status Handler
// ============================================================

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := map[string]string{
		"status": "running",
		"module": "noxis_shield_admin",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ============================================================
// Helpers
// ============================================================

func jsonOK(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
}
