package proxy

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamBackend represents a single backend server endpoint
type UpstreamBackend struct {
	URL      string
	IsDead   atomic.Bool
	Failures atomic.Int32
}

// UpstreamManager handles Load Balancing across multiple upstream endpoints using Round-Robin
type UpstreamManager struct {
	backends []*UpstreamBackend
	current  uint64 // atomic counter for Round-Robin
	mu       sync.RWMutex
}

// NewUpstreamManager creates and initializes a thread-safe load balancer
func NewUpstreamManager(upstreams []string) *UpstreamManager {
	um := &UpstreamManager{
		backends: make([]*UpstreamBackend, 0, len(upstreams)),
	}

	for _, u := range upstreams {
		addr := u
		if strings.HasPrefix(addr, "http://") {
			addr = strings.TrimPrefix(addr, "http://")
		} else if strings.HasPrefix(addr, "https://") {
			addr = strings.TrimPrefix(addr, "https://")
		}

		backend := &UpstreamBackend{
			URL: addr,
		}
		um.backends = append(um.backends, backend)
		log.Printf("[UpstreamManager] Registered backend: %s", addr)
	}

	// Start active health check worker
	go um.healthCheckWorker()

	return um
}

// GetNext returns the next available backend URL using atomic Round-Robin
func (um *UpstreamManager) GetNext() string {
	um.mu.RLock()
	defer um.mu.RUnlock()

	if len(um.backends) == 0 {
		return ""
	}

	// Atomically increment and get the counter
	idx := atomic.AddUint64(&um.current, 1)

	// Fast modulo to find the slot
	targetIdx := (idx - 1) % uint64(len(um.backends))

	return um.backends[targetIdx].URL
}

// MarkFailure records a failure for the specific backend.
// Currently called by pipeline on doUpstreamRequest failure.
func (um *UpstreamManager) MarkFailure(url string) {
	um.mu.RLock()
	defer um.mu.RUnlock()
	for _, backend := range um.backends {
		if backend.URL == url {
			fails := backend.Failures.Add(1)
			if fails >= 3 {
				if backend.IsDead.CompareAndSwap(false, true) {
					log.Printf("[UpstreamManager] Backend %s marked DEAD after %d failures", url, fails)
				}
			}
			break
		}
	}
}

// GetHealthMetrics returns the count of active (healthy) vs total upstreams.
func (um *UpstreamManager) GetHealthMetrics() (active int, total int) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	total = len(um.backends)
	active = 0
	for _, backend := range um.backends {
		if !backend.IsDead.Load() {
			active++
		}
	}
	return active, total
}

// healthCheckWorker periodically probes dead backends to bring them back.
// (Simplified active probing - could be moved to TCP dial later)
func (um *UpstreamManager) healthCheckWorker() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		um.mu.RLock()
		for _, backend := range um.backends {
			if backend.IsDead.Load() {
				// Naive assumption: If it's been dead a while, try to give it a chance
				// In a real load balancer, we would dial the upstream here.
				// For now, we slowly decay failures to let it participate again.
				currentFails := backend.Failures.Load()
				if currentFails > 0 {
					backend.Failures.Add(-1)
				}
				if backend.Failures.Load() == 0 {
					if backend.IsDead.CompareAndSwap(true, false) {
						log.Printf("[UpstreamManager] Backend %s marked HEALTHY again", backend.URL)
					}
				}
			}
		}
		um.mu.RUnlock()
	}
}

// Count returns the number of active upstreams
func (um *UpstreamManager) Count() int {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return len(um.backends)
}
