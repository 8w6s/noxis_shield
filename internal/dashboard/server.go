package dashboard

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed web/*
var webAssets embed.FS

// Server handles serving the static HTML/CSS/JS dashboard
type Server struct {
	port string
}

// New creates a new dashboard static server.
// Note: This binds to the same port as the WebSocket hub to avoid CORS issues.
func New(port string) *Server {
	return &Server{port: port}
}

// RegisterHandlers registers the static file routes onto the default http mux.
// This assumes the WebSocket hub also uses the default http.ServeMux on the same port.
func (s *Server) RegisterHandlers() {
	// Strip the "web" prefix from the embedded filesystem
	subFS, err := fs.Sub(webAssets, "web")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem for dashboard: %v", err)
	}

	// Serve static files at the root
	fileServer := http.FileServer(http.FS(subFS))

	// Register the handler
	http.Handle("/", fileServer)
	log.Printf("[Dashboard] Static UI registered. Accessible at http://localhost%s/", s.port)
}
