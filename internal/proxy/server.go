package proxy

import (
	"log"
	"net"
	"time"

	"github.com/8w6s/noxis/internal/shield"
	"github.com/valyala/fasthttp"
)

// Server embeds the fasthttp web server running the proxy pipeline
type Server struct {
	fastServer *fasthttp.Server
	pipeline   *Pipeline
	listenAddr string
}

// NewServer initializes the proxy listener and binds the pipeline
func NewServer(listenAddr string, pipeline *Pipeline, shield *shield.Shield) *Server {
	fasthttpServer := &fasthttp.Server{
		Handler:            pipeline.ServeHTTP,
		ReadTimeout:        5 * time.Second, // Prevent slowloris
		WriteTimeout:       5 * time.Second,
		IdleTimeout:        15 * time.Second,
		MaxConnsPerIP:      500, // Safe baseline before Anomaly module kicks in
		MaxRequestsPerConn: 1000,
		Name:               "Noxis", // Identify server in Response Headers
	}

	// Add ConnState hook if Shield is available (Userspace drop)
	// This drops the TCP connection before parsing HTTP if IP is blocked
	if shield != nil {
		fasthttpServer.ConnState = func(conn net.Conn, state fasthttp.ConnState) {
			if state == fasthttp.StateNew {
				ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
				if (*shield).IsBlocked(ip) {
					// Drop connection immediately at TCP level
					(*shield).RecordDrop(ip)
					conn.Close()
				}
			}
		}
	}

	return &Server{
		fastServer: fasthttpServer,
		pipeline:   pipeline,
		listenAddr: listenAddr,
	}
}

// Start opens the socket, blocks and serves incoming proxy traffic.
func (s *Server) Start() error {
	log.Printf("[Proxy Server] Starting Noxis L7 Engine on %s", s.listenAddr)
	return s.fastServer.ListenAndServe(s.listenAddr)
}

// Shutdown gracefully shuts down the reverse proxy server
func (s *Server) Shutdown() error {
	log.Println("[Proxy Server] Shutting down gracefully...")
	return s.fastServer.Shutdown()
}
