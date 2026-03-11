package cluster

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds the runtime configuration for the cluster manager.
type Config struct {
	NodeID         string
	Channel        string
	ImportWeight   float64 // scale factor for incoming signal weights (e.g. 0.7)
	PreApplyBlocks bool    // if true, auto-apply blocks from remote nodes
}

// Hooks holds external callbacks the cluster manager will call on received events.
// All hooks are optional — nil means the action is skipped.
type Hooks struct {
	// OnReputationSignal is called when a reputation_signal event is received.
	// The weight passed in is already scaled by ImportWeight.
	OnReputationSignal func(ip, source, reason string, scaledWeight int)

	// OnIPBlocked is called when a remote node blocks an IP and PreApplyBlocks is true.
	OnIPBlocked func(ip, reason string, ttlSeconds int64)

	// OnIPUnblocked is called when a remote node unblocks an IP.
	OnIPUnblocked func(ip string)

	// OnDefenseModeChanged is called when any node changes defense mode.
	// This is informational only — manager does NOT auto-change local mode.
	OnDefenseModeChanged func(nodeID, mode string)
}

// Manager handles Redis Pub/Sub publish and subscribe for the cluster plane.
type Manager struct {
	cfg      Config
	hooks    Hooks
	rdb      *redis.Client
	cnt      counters
	nodes    *nodeRecord
	lastEvAt time.Time

	enabled bool
}

// New creates a new cluster Manager.
// If cfg.Channel is empty it defaults to "noxis:cluster:events".
func New(rdb *redis.Client, cfg Config, hooks Hooks) *Manager {
	if cfg.Channel == "" {
		cfg.Channel = "noxis:cluster:events"
	}
	if cfg.ImportWeight <= 0 || cfg.ImportWeight > 1 {
		cfg.ImportWeight = 0.7
	}
	if cfg.NodeID == "" {
		cfg.NodeID = generateNodeID()
	}
	return &Manager{
		cfg:     cfg,
		hooks:   hooks,
		rdb:     rdb,
		nodes:   newNodeRecord(),
		enabled: true,
	}
}

// Publish sends a ClusterEvent to all other nodes.
// It sets NodeID and Timestamp automatically.
func (m *Manager) Publish(ctx context.Context, event ClusterEvent) {
	event.NodeID = m.cfg.NodeID
	event.Timestamp = time.Now()

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[Cluster] Failed to encode event: %v", err)
		return
	}

	if err := m.rdb.Publish(ctx, m.cfg.Channel, string(data)).Err(); err != nil {
		log.Printf("[Cluster] Failed to publish event: %v", err)
		return
	}
	m.cnt.published.Add(1)
}

// Start subscribes to the cluster channel and processes incoming events.
// Blocks until ctx is cancelled — run in a goroutine.
func (m *Manager) Start(ctx context.Context) {
	sub := m.rdb.Subscribe(ctx, m.cfg.Channel)
	defer sub.Close()

	log.Printf("[Cluster] Node '%s' listening on channel '%s'", m.cfg.NodeID, m.cfg.Channel)

	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[Cluster] Shutting down subscriber")
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			m.handleMessage(msg.Payload)
		}
	}
}

// GetStatus returns a snapshot of cluster health for the dashboard.
func (m *Manager) GetStatus() ClusterStatus {
	return ClusterStatus{
		Enabled:     m.enabled,
		NodeID:      m.cfg.NodeID,
		Published:   m.cnt.published.Load(),
		Received:    m.cnt.received.Load(),
		NodesSeen:   m.nodes.snapshot(),
		LastEventAt: m.lastEvAt,
	}
}

// handleMessage decodes and dispatches a received cluster event.
// Events from this node itself are silently dropped to prevent loops.
func (m *Manager) handleMessage(payload string) {
	var ev ClusterEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		log.Printf("[Cluster] Failed to decode event: %v", err)
		return
	}

	// Drop our own events to prevent processing loops
	if ev.NodeID == m.cfg.NodeID {
		return
	}

	m.cnt.received.Add(1)
	m.lastEvAt = time.Now()
	m.nodes.seen(ev.NodeID)

	log.Printf("[Cluster] Received event type=%s from node=%s ip=%s", ev.Type, ev.NodeID, ev.IP)

	switch ev.Type {
	case EventReputationSignal:
		if m.hooks.OnReputationSignal != nil && ev.Weight > 0 {
			scaled := int(float64(ev.Weight) * m.cfg.ImportWeight)
			if scaled < 1 {
				scaled = 1
			}
			m.hooks.OnReputationSignal(ev.IP, ev.Source, ev.Reason, scaled)
		}

	case EventIPBlocked:
		if m.cfg.PreApplyBlocks && m.hooks.OnIPBlocked != nil && ev.IP != "" {
			m.hooks.OnIPBlocked(ev.IP, "cluster:"+ev.NodeID+":"+ev.Reason, ev.TTL)
		}

	case EventIPUnblocked:
		if m.hooks.OnIPUnblocked != nil && ev.IP != "" {
			m.hooks.OnIPUnblocked(ev.IP)
		}

	case EventDefenseModeChanged:
		// Only informational — log it, do NOT auto change local mode
		if m.hooks.OnDefenseModeChanged != nil {
			m.hooks.OnDefenseModeChanged(ev.NodeID, ev.Mode)
		}
		log.Printf("[Cluster] Remote node %s changed defense mode to %s", ev.NodeID, ev.Mode)

	case EventRuleHitSummary:
		log.Printf("[Cluster] Rule hit from %s: source=%s ip=%s reason=%s", ev.NodeID, ev.Source, ev.IP, ev.Reason)
	}
}

// generateNodeID creates a pseudorandom short node identifier.
func generateNodeID() string {
	// Use timestamp-based ID for simplicity + uniqueness within a deployment.
	// A UUID library is NOT added as a dependency to keep things lean.
	return "noxis-" + time.Now().Format("20060102-150405.000000")
}
