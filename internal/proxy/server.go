package proxy

import (
	"crypto/tls"
	"log"
	"net"
	"time"

	"github.com/8w6s/noxis/config"
	"github.com/8w6s/noxis/internal/logger"
	"github.com/8w6s/noxis/internal/shield"
	"github.com/8w6s/noxis/internal/utils"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/acme/autocert"
)

// Server embeds the fasthttp web server running the proxy pipeline
type Server struct {
	fastServer *fasthttp.Server
	pipeline   *Pipeline
	listenAddr string
	cfg        *config.AppConfig
}

// extractIP safely retrieves the client IP from a net.Addr without panicking.
// Handles *net.TCPAddr directly and falls back to net.SplitHostPort for other types.
func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

// NewServer initializes the proxy listener and binds the pipeline.
// Takes a shield.Shield interface (not a pointer to interface) to avoid anti-pattern.
func NewServer(listenAddr string, pipeline *Pipeline, sh shield.Shield, cfg *config.AppConfig) *Server {
	var handler fasthttp.RequestHandler = pipeline.ServeHTTP

	// Phase 8: Wire up Access Logger if path is provided
	if cfg != nil && cfg.Log.AccessLogPath != "" {
		handler = logger.NewAccessLogger(cfg.Log.AccessLogPath, handler, cfg).ServeHTTP
	}

	// Phase 9: Real-IP Extraction wrapper at the very edge
	edgeHandler := func(ctx *fasthttp.RequestCtx) {
		if cfg != nil {
			realIP := utils.ExtractClientIP(ctx, cfg)
			ctx.SetUserValue("RealIP", realIP)
		}
		handler(ctx)
	}

	fasthttpServer := &fasthttp.Server{
		Handler:            edgeHandler,
		ReadTimeout:        5 * time.Second,  // Prevent slowloris
		WriteTimeout:       5 * time.Second,
		IdleTimeout:        15 * time.Second,
		MaxRequestsPerConn: 1000,
		MaxRequestBodySize: 4 * 1024 * 1024, // 4MB
		Name:               "NoxisShield/1.0", // Identify server in Response Headers
	}

	// Add ConnState hook if Shield is available (Userspace drop).
	// This drops the TCP connection before parsing HTTP if IP is blocked.
	if sh != nil {
		fasthttpServer.ConnState = func(conn net.Conn, state fasthttp.ConnState) {
			if state == fasthttp.StateNew {
				ip := extractIP(conn.RemoteAddr())
				if ip != "" && sh.IsBlocked(ip) {
					// Drop connection immediately at TCP level
					sh.RecordDrop(ip)
					conn.Close()
				}
			}
		}
	}

	return &Server{
		fastServer: fasthttpServer,
		pipeline:   pipeline,
		listenAddr: listenAddr,
		cfg:        cfg,
	}
}

// Start opens the socket, blocks and serves incoming proxy traffic.
// If Auto-TLS is enabled, it automatically binds to the TLS socket using Let's Encrypt endpoints.
func (s *Server) Start() error {
	if s.cfg != nil && s.cfg.TLS.Enabled {
		log.Printf("[Proxy Server] Starting Noxis Shield on %s with Auto-TLS (Let's Encrypt)", s.listenAddr)

		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.cfg.TLS.Domains...),
			Cache:      autocert.DirCache("certs"), // Cache certificates in "certs" directory
			Email:      s.cfg.TLS.Email,
		}

		tlsConfig := m.TLSConfig()

		ln, err := net.Listen("tcp", s.listenAddr)
		if err != nil {
			return err
		}
		tlsListener := tls.NewListener(ln, tlsConfig)

		return s.fastServer.Serve(tlsListener)
	}

	log.Printf("[Proxy Server] Starting Noxis Shield on %s (HTTP)", s.listenAddr)
	return s.fastServer.ListenAndServe(s.listenAddr)
}

// Shutdown gracefully shuts down the reverse proxy server
func (s *Server) Shutdown() error {
	log.Println("[Proxy Server] Shutting down gracefully...")
	return s.fastServer.Shutdown()
}
