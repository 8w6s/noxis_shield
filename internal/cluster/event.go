package cluster

import "time"

// EventType identifies what kind of cluster event is being shared
type EventType string

const (
	// EventIPBlocked is published when a node blocks an IP
	EventIPBlocked EventType = "ip_blocked"
	// EventIPUnblocked is published when a node unblocks an IP
	EventIPUnblocked EventType = "ip_unblocked"
	// EventReputationSignal shares a reputation/signal score update
	EventReputationSignal EventType = "reputation_signal"
	// EventDefenseModeChanged is published when a node changes defense mode
	EventDefenseModeChanged EventType = "defense_mode_changed"
	// EventRuleHitSummary shares a WAF/policy rule hit event
	EventRuleHitSummary EventType = "rule_hit_summary"
)

// ClusterEvent represents a single shareable event between Noxis nodes.
// All fields are deliberately simple for fast JSON encode/decode over Redis.
type ClusterEvent struct {
	Type      EventType         `json:"type"`
	NodeID    string            `json:"nodeId"`
	IP        string            `json:"ip,omitempty"`
	Source    string            `json:"source,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Severity  string            `json:"severity,omitempty"`
	Weight    int               `json:"weight,omitempty"`
	TTL       int64             `json:"ttl,omitempty"`    // seconds
	Mode      string            `json:"mode,omitempty"`   // for defense_mode_changed
	Meta      map[string]string `json:"meta,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}
