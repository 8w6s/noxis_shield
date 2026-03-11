package cluster

import (
	"sync/atomic"
	"sync"
	"time"
)

// Stats tracks cluster plane operational metrics.
type Stats struct {
	Published int64
	Received  int64
}

// nodeRecord tracks when a remote node was last seen
type nodeRecord struct {
	mu       sync.RWMutex
	lastSeen map[string]time.Time
}

func newNodeRecord() *nodeRecord {
	return &nodeRecord{lastSeen: make(map[string]time.Time)}
}

func (n *nodeRecord) seen(nodeID string) {
	n.mu.Lock()
	n.lastSeen[nodeID] = time.Now()
	n.mu.Unlock()
}

func (n *nodeRecord) snapshot() map[string]time.Time {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make(map[string]time.Time, len(n.lastSeen))
	for k, v := range n.lastSeen {
		out[k] = v
	}
	return out
}

// ClusterStatus is a snapshot of the cluster plane for dashboard/health reporting.
type ClusterStatus struct {
	Enabled     bool
	NodeID      string
	Published   int64
	Received    int64
	NodesSeen   map[string]time.Time
	LastEventAt time.Time
}

// counters holds atomic stats
type counters struct {
	published atomic.Int64
	received  atomic.Int64
}
