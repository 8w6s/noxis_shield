package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/8w6s/noxis/internal/metrics"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow all origins for the dashboard
		return true
	},
}

// Hub maintains the set of active clients and broadcasts messages to the clients.
type Hub struct {
	// Registered clients.
	clients map[*websocket.Conn]bool

	// Mutex for protecting the clients map
	mu sync.RWMutex

	// Inbound messages from the server to broadcast
	broadcast chan metrics.Stats

	port       string
	aggregator *metrics.Aggregator
}

// New creates a new WebSocket hub.
func New(port string, aggregator *metrics.Aggregator) *Hub {
	return &Hub{
		broadcast:  make(chan metrics.Stats),
		clients:    make(map[*websocket.Conn]bool),
		port:       port,
		aggregator: aggregator,
	}
}

// Start begins the hub background worker and HTTP listener.
func (h *Hub) Start() error {
	log.Printf("[WebSocket] Starting Dashboard Hub on %s", h.port)

	// Background routine to broadcast metrics
	go h.run()

	// Routine to compile and send stats every second
	go h.emitter()

	http.HandleFunc("/ws", h.handleConnections)
	return http.ListenAndServe(h.port, nil)
}

func (h *Hub) handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebSocket] Failed to upgrade connection: %v", err)
		return
	}

	// Register new client
	h.mu.Lock()
	h.clients[ws] = true
	h.mu.Unlock()

	log.Printf("[WebSocket] New Dashboard client connected. Total: %d", len(h.clients))

	// Ensure cleanup on disconnect
	defer func() {
		h.mu.Lock()
		delete(h.clients, ws)
		ws.Close()
		h.mu.Unlock()
	}()

	// Keep connection alive, listen for close
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (h *Hub) run() {
	for {
		stats := <-h.broadcast

		msg, err := json.Marshal(stats)
		if err != nil {
			log.Printf("[WebSocket] JSON marshal error: %v", err)
			continue
		}

		h.mu.RLock()
		for client := range h.clients {
			// Write JSON message to client
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				log.Printf("[WebSocket] Client dropped connection")
				client.Close()
				h.mu.RUnlock()

				h.mu.Lock()
				delete(h.clients, client)
				h.mu.Unlock()

				h.mu.RLock()
			}
		}
		h.mu.RUnlock()
	}
}

func (h *Hub) emitter() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Pull snapshot from the central aggregator
		snapshot := h.aggregator.CompileSnapshot()

		// Send to the hub broadcaster
		h.broadcast <- snapshot
	}
}
