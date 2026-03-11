package signals

import "time"

// Severity represents the danger level of a detected signal.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Signal represents a single suspicious-behavior event emitted by any detection module.
// It is the common currency of the unified decision layer.
type Signal struct {
	IP        string
	Source    string   // "waf", "ratelimit", "challenge", "anomaly", "reputation", "cluster"
	Reason    string
	Severity  Severity
	Weight    int           // score contribution (positive = bad, negative = reward)
	TTL       time.Duration // optional: if set, score contribution decays after TTL (future use)
	Meta      map[string]string
	Timestamp time.Time
}

// OffenderEntry is a snapshot of a single IP's current threat score. Used for the dashboard.
type OffenderEntry struct {
	IP         string   `json:"ip"`
	Score      int      `json:"score"`
	LastSource string   `json:"lastSource"`
	LastReason string   `json:"lastReason"`
	LastSeen   int64    `json:"lastSeen"` // Unix timestamp
}
