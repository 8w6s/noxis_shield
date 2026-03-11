package reputation

import (
	"log"
	"sync"
	"time"
)

// DataBlock represents the behavior track record of a single IP address.
type DataBlock struct {
	IP       string
	Requests int64
	Score    float64
	LastSeen time.Time
}

// Manager handles the behavior scoring and aggregation for all IPs.
type Manager struct {
	blocks    map[string]*DataBlock
	mu        sync.RWMutex
	threshold float64
}

// New creates a new Reputation Manager evaluating IPs against a set threshold.
func New(threshold float64) *Manager {
	m := &Manager{
		blocks:    make(map[string]*DataBlock),
		threshold: threshold,
	}

	// Background cleanup of stale DataBlocks (free memory)
	go m.cleanupLoop()
	return m
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for ip, block := range m.blocks {
			// If we haven't seen the IP in 10 minutes, clear its reputation score to save RAM
			if now.Sub(block.LastSeen) > 10*time.Minute {
				delete(m.blocks, ip)
			}
		}
		m.mu.Unlock()
	}
}

// RecordHit registers a request from an IP. It returns true if the IP's reputation score exceeds the threshold.
func (m *Manager) RecordHit(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	block, exists := m.blocks[ip]
	now := time.Now()

	if !exists {
		block = &DataBlock{
			IP:       ip,
			Requests: 1,
			Score:    0,
			LastSeen: now,
		}
		m.blocks[ip] = block
		return false
	}

	block.Requests++

	// 1. Behavior Rule: Rate of Arrival Penalization
	timeSinceLast := now.Sub(block.LastSeen).Seconds()

	// If requests are arriving faster than 10 req/s, penalize the behavior score.
	if timeSinceLast < 0.1 {
		block.Score += 0.5
	} else if timeSinceLast > 2.0 {
		// Reward good behavior (cooling off)
		block.Score -= 0.1
		if block.Score < 0 {
			block.Score = 0
		}
	}

	block.LastSeen = now

	return block.Score >= m.threshold
}

// Penalize adds a fixed penalty points to a specific IP (e.g., from Anomaly baseline detection)
func (m *Manager) Penalize(ip string, penalty float64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	block, exists := m.blocks[ip]
	if !exists {
		block = &DataBlock{
			IP:       ip,
			Requests: 0,
			Score:    0,
			LastSeen: time.Now(),
		}
		m.blocks[ip] = block
	}

	block.Score += penalty
	log.Printf("[Reputation] IP %s penalized by %v. New score: %.2f", ip, penalty, block.Score)

	return block.Score >= m.threshold
}

// GetScore returns the current behavior score of an IP without modifying its last seen timestamp
func (m *Manager) GetScore(ip string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if block, exists := m.blocks[ip]; exists {
		return block.Score
	}
	return 0.0
}
