package metrics

import (
	"sync/atomic"
	"time"

	"github.com/8w6s/noxis/internal/cluster"
	"github.com/8w6s/noxis/internal/defense"
	"github.com/8w6s/noxis/internal/shield"
	"github.com/8w6s/noxis/internal/signals"
)

// Global stats that are pushed to the dashboard
type Stats struct {
	Timestamp         int64         `json:"timestamp"`
	CurrentRPS        float64       `json:"currentRPS"`
	PeakRPS           float64       `json:"peakRPS"`
	TotalRequests     int64         `json:"totalRequests"`
	Blocked           int64         `json:"blocked"`
	Passed            int64         `json:"passed"`
	BannedIPs         int64         `json:"bannedIPs"`
	ActiveConnections int64         `json:"activeConnections"`
	EbpfDrops         int64         `json:"ebpfDrops"`
	Status            string                  `json:"status"`
	Health            SubsystemHealth         `json:"health"`
	RecentEvents      []AttackEvent           `json:"recentEvents"`
	TopOffenders      []signals.OffenderEntry `json:"topOffenders"`
}

// SubsystemHealth holds the status of all core components.
type SubsystemHealth struct {
	ShieldState       string `json:"shieldState"`
	RedisReachable    bool   `json:"redisReachable"`
	WAFEnabled        bool   `json:"wafEnabled"`
	UpstreamsActive   int    `json:"upstreamsActive"`
	UpstreamsTotal    int    `json:"upstreamsTotal"`
	ReconcilerLastRun int64  `json:"reconcilerLastRun"`
	DefenseMode       string `json:"defenseMode"`
	// Cluster fields (zero-value when cluster not enabled)
	ClusterEnabled   bool   `json:"clusterEnabled"`
	ClusterNodeID    string `json:"clusterNodeId,omitempty"`
	ClusterPublished int64  `json:"clusterPublished,omitempty"`
	ClusterReceived  int64  `json:"clusterReceived,omitempty"`
	ClusterNodeCount int    `json:"clusterNodeCount,omitempty"`
}

type AttackEvent struct {
	Time   string `json:"time"`
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// Aggregator centralizes metrics collection across the entire proxy.
type Aggregator struct {
	TotalReqs *atomic.Int64
	Blocked   *atomic.Int64
	Passed    *atomic.Int64
	ActiveC   *atomic.Int64
	PeakRPS   *atomic.Value // holds float64

	currentRPS float64
	status     string
	events     []AttackEvent

	shield    shield.Shield
	sigEngine *signals.Engine // Optional reference to fetch real-time Top Offenders

	// Dependencies for health checks
	getRedisHealth     func() bool
	getWAFEnabled      func() bool
	getUpstreamHealth  func() (active, total int)
	getReconcilerState func() int64
	getDefenseMode     func() defense.Mode
	getClusterStatus   func() cluster.ClusterStatus
}

// New creates a new Metrics Aggregator
func New(shield shield.Shield) *Aggregator {
	a := &Aggregator{
		TotalReqs: &atomic.Int64{},
		Blocked:   &atomic.Int64{},
		Passed:    &atomic.Int64{},
		ActiveC:   &atomic.Int64{},
		PeakRPS:   &atomic.Value{},
		status:    "normal",
		events:    make([]AttackEvent, 0),
		shield:    shield,
	}
	a.PeakRPS.Store(0.0)
	return a
}

// WithSignals allows injecting the unified signal engine to fetch real-time offenders
func (a *Aggregator) WithSignals(e *signals.Engine) *Aggregator {
	a.sigEngine = e
	return a
}

// WithHealthChecks injects functions needed to query subsystem health at snapshot time.
func (a *Aggregator) WithHealthChecks(
	redisHealth func() bool,
	wafEnabled func() bool,
	upstreamHealth func() (active, total int),
	reconcilerState func() int64,
	defenseMode func() defense.Mode,
) *Aggregator {
	a.getRedisHealth = redisHealth
	a.getWAFEnabled = wafEnabled
	a.getUpstreamHealth = upstreamHealth
	a.getReconcilerState = reconcilerState
	a.getDefenseMode = defenseMode
	return a
}

// WithCluster injects the cluster status callback
func (a *Aggregator) WithCluster(fn func() cluster.ClusterStatus) *Aggregator {
	a.getClusterStatus = fn
	return a
}

// RecordRequest increments total requests
func (a *Aggregator) RecordRequest() {
	a.TotalReqs.Add(1)
}

// RecordBlock increments blocked counter
func (a *Aggregator) RecordBlock() {
	a.Blocked.Add(1)
}

// RecordPass increments passed counter
func (a *Aggregator) RecordPass() {
	a.Passed.Add(1)
}

// AddActiveConnection increments active connections
func (a *Aggregator) AddActiveConnection() {
	a.ActiveC.Add(1)
}

// RemoveActiveConnection decrements active connections
func (a *Aggregator) RemoveActiveConnection() {
	a.ActiveC.Add(-1)
}

// SetCurrentRPS updates current RPS and tracks peak
func (a *Aggregator) SetCurrentRPS(rps float64) {
	a.currentRPS = rps
	peak := a.PeakRPS.Load().(float64)
	if rps > peak {
		a.PeakRPS.Store(rps)
	}
}

// SetStatus updates system status (normal, under_attack, stable)
func (a *Aggregator) SetStatus(status string) {
	a.status = status
}

// AddEvent adds a new event to the feed (keeps last 50)
func (a *Aggregator) AddEvent(eventType, detail string) {
	event := AttackEvent{
		Time:   time.Now().Format("15:04:05"),
		Type:   eventType,
		Detail: detail,
	}

	a.events = append([]AttackEvent{event}, a.events...)
	if len(a.events) > 50 {
		a.events = a.events[:50]
	}
}

// CompileSnapshot gathers all metrics into a single struct suitable for JSON export
func (a *Aggregator) CompileSnapshot() Stats {
	ebpfDrops := a.shield.GetDropCount()
	// Fetch top 5 offenders directly from in-memory engine (if attached)
	var topOffenders []signals.OffenderEntry
	if a.sigEngine != nil {
		topOffenders = a.sigEngine.GetTopOffenders(5)
	}

	shieldState := "attached"
	if _, ok := a.shield.(interface{ IsUserspace() bool }); ok {
		shieldState = "userspace_fallback"
	}

	health := SubsystemHealth{
		ShieldState: shieldState,
	}

	if a.getRedisHealth != nil {
		health.RedisReachable = a.getRedisHealth()
	}
	if a.getWAFEnabled != nil {
		health.WAFEnabled = a.getWAFEnabled()
	}
	if a.getUpstreamHealth != nil {
		health.UpstreamsActive, health.UpstreamsTotal = a.getUpstreamHealth()
	}
	if a.getReconcilerState != nil {
		health.ReconcilerLastRun = a.getReconcilerState()
	}
	if a.getDefenseMode != nil {
		health.DefenseMode = string(a.getDefenseMode())
	}
	if a.getClusterStatus != nil {
		cStat := a.getClusterStatus()
		health.ClusterEnabled = cStat.Enabled
		health.ClusterNodeID = cStat.NodeID
		health.ClusterPublished = cStat.Published
		health.ClusterReceived = cStat.Received
		health.ClusterNodeCount = len(cStat.NodesSeen)
	}

	return Stats{
		Timestamp:         time.Now().UnixMilli(),
		CurrentRPS:        a.currentRPS,
		PeakRPS:           a.PeakRPS.Load().(float64),
		TotalRequests:     a.TotalReqs.Load() + ebpfDrops,
		Blocked:           a.Blocked.Load() + ebpfDrops,
		Passed:            a.Passed.Load(),
		ActiveConnections: a.ActiveC.Load(),
		EbpfDrops:         ebpfDrops,
		Status:            a.status,
		Health:            health,
		RecentEvents:      a.events,
		TopOffenders:      topOffenders,
		BannedIPs:         0,
	}
}
