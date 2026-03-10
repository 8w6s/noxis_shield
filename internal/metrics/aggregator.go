package metrics

import (
	"sync/atomic"
	"time"

	"github.com/8w6s/noxis/internal/anomaly"
	"github.com/8w6s/noxis/internal/shield"
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
	Status            string        `json:"status"`
	RecentEvents      []AttackEvent `json:"recentEvents"`
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

	detector *anomaly.Detector
	shield   shield.Shield
}

// New creates a new Metrics Aggregator
func New(detector *anomaly.Detector, shield shield.Shield) *Aggregator {
	a := &Aggregator{
		TotalReqs: &atomic.Int64{},
		Blocked:   &atomic.Int64{},
		Passed:    &atomic.Int64{},
		ActiveC:   &atomic.Int64{},
		PeakRPS:   &atomic.Value{},
		status:    "normal",
		events:    make([]AttackEvent, 0),
		detector:  detector,
		shield:    shield,
	}
	a.PeakRPS.Store(0.0)
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
	return Stats{
		Timestamp:         time.Now().UnixMilli(),
		CurrentRPS:        a.currentRPS,
		PeakRPS:           a.PeakRPS.Load().(float64),
		TotalRequests:     a.TotalReqs.Load(),
		Blocked:           a.Blocked.Load() + a.shield.GetDropCount(),
		Passed:            a.Passed.Load(),
		ActiveConnections: a.ActiveC.Load(),
		EbpfDrops:         a.shield.GetDropCount(),
		Status:            a.status,
		RecentEvents:      a.events,
		// BannedIPs would be fetched asynchronously from Redis in a real hook
		BannedIPs: 0,
	}
}
