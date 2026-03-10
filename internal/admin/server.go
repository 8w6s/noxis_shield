package admin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/8w6s/noxis/internal/blocklist"
)

// Server provides a local API for the NoxCtl CLI to manage the engine
type Server struct {
	port      string
	blManager *blocklist.Manager
}

// New creates a new admin API server
func New(port string, blManager *blocklist.Manager) *Server {
	return &Server{
		port:      port,
		blManager: blManager,
	}
}

// Start boots up the admin HTTP server on the localhost interface.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/block", s.handleBlock)
	mux.HandleFunc("/api/unblock", s.handleUnblock)
	mux.HandleFunc("/api/status", s.handleStatus)

	log.Printf("[Admin] API Server listening on %s", s.port)
	return http.ListenAndServe(s.port, mux)
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "Missing 'ip' query parameter", http.StatusBadRequest)
		return
	}

	// Manual blocks from CLI are marked with reason 'manual_cli'
	err := s.blManager.Block(r.Context(), ip, "manual_cli")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to block IP: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Successfully blocked IP: %s\n", ip)))
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

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Successfully unblocked IP: %s\n", ip)))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// A quick health check
	resp := map[string]string{
		"status": "running",
		"module": "noxis_shield_admin",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
