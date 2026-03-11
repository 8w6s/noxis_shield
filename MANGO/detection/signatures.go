package detection

import (
	"fmt"
	"sync"
	"time"
)

// AttackDetector detects and classifies DDoS attack patterns
type AttackDetector struct {
	signatures   []AttackSignature
	activeAlerts sync.Map // map[string]*AttackAlert
	history      []AttackEvent
	mu           sync.RWMutex
}

// AttackSignature defines an attack pattern
type AttackSignature struct {
	ID          string
	Name        string
	Type        string // volumetric, slowloris, http_flood, api_abuse, credential_stuffing
	Description string
	Severity    string // low, medium, high, critical
	CheckFn     func(snap *TrafficSnapshot) bool
}

// TrafficSnapshot represents current traffic metrics for detection
type TrafficSnapshot struct {
	CurrentRPS    int64
	PeakRPS       int64
	BaselineRPS   float64
	ActiveConns   int64
	UniqueIPs     int64
	NewIPsPerSec  int64
	AvgReqSize    float64
	MethodDistrib map[string]int64 // GET, POST, PUT, etc.
	StatusDistrib map[int]int64    // 2xx, 4xx, 5xx counts
	TopPaths      map[string]int64
	TopIPs        map[string]int64
	AvgLatency    float64
	ErrorRate     float64
	BotPercentage float64
	TCPHalfOpen   int64
	SlowConns     int64 // connections alive > 30s
}

// AttackAlert represents an active attack detection
type AttackAlert struct {
	ID          string
	SignatureID string
	Type        string
	Severity    string
	StartTime   time.Time
	LastSeen    time.Time
	PeakRPS     int64
	Mitigated   bool
	Details     map[string]interface{}
}

// AttackEvent is a historical attack record
type AttackEvent struct {
	ID        string
	Type      string
	Severity  string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	PeakRPS   int64
	TotalReqs int64
	Blocked   int64
	TopIPs    []string
}

// NewAttackDetector creates a new attack detector with built-in signatures
func NewAttackDetector() *AttackDetector {
	ad := &AttackDetector{}
	ad.loadSignatures()
	return ad
}

// Detect runs all signatures against current traffic snapshot
func (ad *AttackDetector) Detect(snap *TrafficSnapshot) []*AttackAlert {
	var alerts []*AttackAlert

	for _, sig := range ad.signatures {
		if sig.CheckFn(snap) {
			alertKey := sig.ID
			existing, loaded := ad.activeAlerts.Load(alertKey)

			if loaded {
				// Update existing alert
				alert := existing.(*AttackAlert)
				alert.LastSeen = time.Now()
				if snap.CurrentRPS > alert.PeakRPS {
					alert.PeakRPS = snap.CurrentRPS
				}
				alerts = append(alerts, alert)
			} else {
				// New attack detected
				alert := &AttackAlert{
					ID:          fmt.Sprintf("%s_%d", sig.ID, time.Now().Unix()),
					SignatureID: sig.ID,
					Type:        sig.Type,
					Severity:    sig.Severity,
					StartTime:   time.Now(),
					LastSeen:    time.Now(),
					PeakRPS:     snap.CurrentRPS,
					Details:     make(map[string]interface{}),
				}
				ad.activeAlerts.Store(alertKey, alert)
				alerts = append(alerts, alert)
			}
		}
	}

	// Check for ended attacks (no match for 30 seconds)
	ad.activeAlerts.Range(func(key, value interface{}) bool {
		alert := value.(*AttackAlert)
		if time.Since(alert.LastSeen) > 30*time.Second {
			alert.Mitigated = true
			ad.recordEvent(alert)
			ad.activeAlerts.Delete(key)
		}
		return true
	})

	return alerts
}

// recordEvent records attack event to history
func (ad *AttackDetector) recordEvent(alert *AttackAlert) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	event := AttackEvent{
		ID:        alert.ID,
		Type:      alert.Type,
		Severity:  alert.Severity,
		StartTime: alert.StartTime,
		EndTime:   time.Now(),
		Duration:  time.Since(alert.StartTime),
		PeakRPS:   alert.PeakRPS,
	}

	ad.history = append(ad.history, event)

	// Keep max 1000 events
	if len(ad.history) > 1000 {
		ad.history = ad.history[len(ad.history)-1000:]
	}
}

// GetHistory returns attack history
func (ad *AttackDetector) GetHistory(limit int) []AttackEvent {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if limit <= 0 || limit > len(ad.history) {
		limit = len(ad.history)
	}
	start := len(ad.history) - limit
	result := make([]AttackEvent, limit)
	copy(result, ad.history[start:])
	return result
}

// GetActiveAlerts returns currently active attack alerts
func (ad *AttackDetector) GetActiveAlerts() []*AttackAlert {
	var alerts []*AttackAlert
	ad.activeAlerts.Range(func(_, value interface{}) bool {
		alerts = append(alerts, value.(*AttackAlert))
		return true
	})
	return alerts
}

// loadSignatures loads built-in attack signatures
func (ad *AttackDetector) loadSignatures() {
	ad.signatures = []AttackSignature{
		// --- Volumetric HTTP Flood ---
		{
			ID:          "http_flood_medium",
			Name:        "HTTP Flood (Medium)",
			Type:        "http_flood",
			Severity:    "medium",
			Description: "RPS significantly above baseline",
			CheckFn: func(snap *TrafficSnapshot) bool {
				if snap.BaselineRPS == 0 {
					return snap.CurrentRPS > 500
				}
				return float64(snap.CurrentRPS) > snap.BaselineRPS*3
			},
		},
		{
			ID:          "http_flood_high",
			Name:        "HTTP Flood (High)",
			Type:        "http_flood",
			Severity:    "high",
			Description: "Massive RPS spike detected",
			CheckFn: func(snap *TrafficSnapshot) bool {
				if snap.BaselineRPS == 0 {
					return snap.CurrentRPS > 2000
				}
				return float64(snap.CurrentRPS) > snap.BaselineRPS*8
			},
		},
		{
			ID:          "http_flood_critical",
			Name:        "HTTP Flood (Critical)",
			Type:        "http_flood",
			Severity:    "critical",
			Description: "Extreme flood — server at capacity",
			CheckFn: func(snap *TrafficSnapshot) bool {
				if snap.BaselineRPS == 0 {
					return snap.CurrentRPS > 10000
				}
				return float64(snap.CurrentRPS) > snap.BaselineRPS*20
			},
		},

		// --- Slowloris ---
		{
			ID:          "slowloris",
			Name:        "Slowloris Attack",
			Type:        "slowloris",
			Severity:    "high",
			Description: "Many slow connections holding resources",
			CheckFn: func(snap *TrafficSnapshot) bool {
				return snap.SlowConns > 50 && snap.ActiveConns > 200
			},
		},

		// --- Connection Exhaustion ---
		{
			ID:          "conn_exhaustion",
			Name:        "Connection Exhaustion",
			Type:        "conn_exhaustion",
			Severity:    "high",
			Description: "Abnormally high number of open connections",
			CheckFn: func(snap *TrafficSnapshot) bool {
				return snap.ActiveConns > 5000
			},
		},

		// --- API Abuse ---
		{
			ID:          "api_abuse",
			Name:        "API Abuse",
			Type:        "api_abuse",
			Severity:    "medium",
			Description: "Targeted API endpoint flooding",
			CheckFn: func(snap *TrafficSnapshot) bool {
				if len(snap.TopPaths) == 0 {
					return false
				}
				// Check if single path gets >60% of traffic
				maxPath := int64(0)
				totalReqs := int64(0)
				for _, count := range snap.TopPaths {
					if count > maxPath {
						maxPath = count
					}
					totalReqs += count
				}
				if totalReqs == 0 {
					return false
				}
				return float64(maxPath)/float64(totalReqs) > 0.6 && totalReqs > 100
			},
		},

		// --- Credential Stuffing ---
		{
			ID:          "credential_stuffing",
			Name:        "Credential Stuffing",
			Type:        "credential_stuffing",
			Severity:    "high",
			Description: "Mass login attempts from multiple IPs",
			CheckFn: func(snap *TrafficSnapshot) bool {
				postCount := snap.MethodDistrib["POST"]
				loginReqs := int64(0)
				for path, count := range snap.TopPaths {
					if isLoginPath(path) {
						loginReqs += count
					}
				}
				return postCount > 50 && loginReqs > 30
			},
		},

		// --- Bot Swarm ---
		{
			ID:          "bot_swarm",
			Name:        "Bot Swarm Detected",
			Type:        "bot_swarm",
			Severity:    "high",
			Description: "High percentage of bot traffic",
			CheckFn: func(snap *TrafficSnapshot) bool {
				return snap.BotPercentage > 0.7 && snap.CurrentRPS > 100
			},
		},

		// --- IP Rotation Attack ---
		{
			ID:          "ip_rotation",
			Name:        "IP Rotation Attack",
			Type:        "ip_rotation",
			Severity:    "high",
			Description: "Many new IPs appearing rapidly",
			CheckFn: func(snap *TrafficSnapshot) bool {
				return snap.NewIPsPerSec > 50
			},
		},

		// --- Error-based Detection ---
		{
			ID:          "error_spike",
			Name:        "Error Rate Spike",
			Type:        "scanning",
			Severity:    "medium",
			Description: "Abnormally high error rate",
			CheckFn: func(snap *TrafficSnapshot) bool {
				return snap.ErrorRate > 0.4 && snap.CurrentRPS > 50
			},
		},
	}
}

func isLoginPath(path string) bool {
	loginPaths := []string{"/login", "/signin", "/auth", "/api/login", "/api/auth", "/wp-login.php"}
	for _, lp := range loginPaths {
		if path == lp {
			return true
		}
	}
	return false
}
