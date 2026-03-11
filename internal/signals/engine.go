package signals

import (
	"log"
	"sort"
	"sync"
	"time"
)

// EscalationConfig defines thresholds and actions triggered by the ScoreEngine.
// All callbacks are optional — if nil, the action is silently skipped.
type EscalationConfig struct {
	ChallengeThreshold int // score at which challenge is suggested (default: 25)
	ElevatedThreshold  int // score at which elevated warnings fire (default: 50)
	BlockThreshold     int // score at which IP is sent to blocklist (default: 80)

	// OnChallenge is called when an IP crosses ChallengeThreshold.
	// It is informational only — does not stop the current request.
	OnChallenge func(ip string)

	// OnBlock is called when an IP crosses BlockThreshold.
	// Typically wires to blocklist.BlockWithSource.
	OnBlock func(ip, reason string)

	// OnEmit is called whenever an IP receives a signal (before thresholds check).
	OnEmit func(ip, source, reason string, weight int)
}

// ipState holds per-IP score and metadata inside the engine.
type ipState struct {
	score      int
	lastSource string
	lastReason string
	lastSeen   time.Time
}

// Engine is the unified signal accumulator and escalation decision maker.
// It is safe for concurrent use.
type Engine struct {
	mu         sync.RWMutex
	states     map[string]*ipState
	whitelist  map[string]struct{} // IPs that bypass escalation
	cfg        EscalationConfig
	decayRate  float64 // fraction of score to remove per decay tick (0.10 = 10%)
}

// NewEngine creates a new Engine with the given escalation config.
// The decay worker is started via Start(ctx).
func NewEngine(cfg EscalationConfig) *Engine {
	// Apply defaults
	if cfg.ChallengeThreshold <= 0 {
		cfg.ChallengeThreshold = 25
	}
	if cfg.ElevatedThreshold <= 0 {
		cfg.ElevatedThreshold = 50
	}
	if cfg.BlockThreshold <= 0 {
		cfg.BlockThreshold = 80
	}

	return &Engine{
		states:    make(map[string]*ipState),
		whitelist: make(map[string]struct{}),
		cfg:       cfg,
		decayRate: 0.10, // 10% decay per tick
	}
}

// Start begins the background decay worker. Stops when ctx is cancelled.
func (e *Engine) Start(ctx interface{ Done() <-chan struct{} }) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.decay()
			}
		}
	}()
}

// Bypass adds an IP to the engine's whitelist.
// Whitelisted IPs still accumulate signals (for logging) but are never escalated.
func (e *Engine) Bypass(ip string) {
	e.mu.Lock()
	e.whitelist[ip] = struct{}{}
	e.mu.Unlock()
}

// Emit records a signal and applies its weight to the source IP's score.
// If the resulting score crosses a threshold, the appropriate callback is fired.
func (e *Engine) Emit(sig Signal) {
	if sig.IP == "" {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Get or create state
	state, ok := e.states[sig.IP]
	if !ok {
		state = &ipState{}
		e.states[sig.IP] = state
	}

	// Apply weight (can be negative for rewards)
	prev := state.score
	state.score += sig.Weight
	if state.score < 0 {
		state.score = 0
	}

	state.lastSource = sig.Source
	state.lastReason = sig.Reason
	state.lastSeen = sig.Timestamp
	if state.lastSeen.IsZero() {
		state.lastSeen = time.Now()
	}

	if sig.Weight != 0 {
		log.Printf("[Signals] IP=%s source=%s reason=%q weight=%+d score: %d→%d",
			sig.IP, sig.Source, sig.Reason, sig.Weight, prev, state.score)
	}

	// Whitelisted IPs: log only, no escalation
	_, whitelisted := e.whitelist[sig.IP]
	if whitelisted {
		if e.cfg.OnEmit != nil {
			go e.cfg.OnEmit(sig.IP, sig.Source, sig.Reason, sig.Weight)
		}
		return
	}

	if e.cfg.OnEmit != nil {
		go e.cfg.OnEmit(sig.IP, sig.Source, sig.Reason, sig.Weight)
	}

	e.checkThresholds(sig.IP, state, prev)
}

// checkThresholds fires escalation callbacks if score crossed a threshold during this emit.
// Must be called with e.mu held.
func (e *Engine) checkThresholds(ip string, state *ipState, prevScore int) {
	score := state.score

	// Block threshold
	if score >= e.cfg.BlockThreshold && prevScore < e.cfg.BlockThreshold {
		log.Printf("[Signals] IP=%s crossed BLOCK threshold (score=%d). Escalating to blocklist.", ip, score)
		if e.cfg.OnBlock != nil {
			reason := state.lastReason
			go e.cfg.OnBlock(ip, reason)
		}
		// Reset score so escalation doesn't loop
		state.score = 0
		return
	}

	// Elevated threshold
	if score >= e.cfg.ElevatedThreshold && prevScore < e.cfg.ElevatedThreshold {
		log.Printf("[Signals] IP=%s crossed ELEVATED threshold (score=%d).", ip, score)
	}

	// Challenge threshold
	if score >= e.cfg.ChallengeThreshold && prevScore < e.cfg.ChallengeThreshold {
		log.Printf("[Signals] IP=%s crossed CHALLENGE threshold (score=%d).", ip, score)
		if e.cfg.OnChallenge != nil {
			go e.cfg.OnChallenge(ip)
		}
	}
}

// GetScore returns the current threat score for an IP.
func (e *Engine) GetScore(ip string) int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if state, ok := e.states[ip]; ok {
		return state.score
	}
	return 0
}

// GetTopOffenders returns the top N IPs by current score.
// Used by the dashboard.
func (e *Engine) GetTopOffenders(n int) []OffenderEntry {
	e.mu.RLock()
	entries := make([]OffenderEntry, 0, len(e.states))
	for ip, state := range e.states {
		if state.score > 0 {
			entries = append(entries, OffenderEntry{
				IP:         ip,
				Score:      state.score,
				LastSource: state.lastSource,
				LastReason: state.lastReason,
				LastSeen:   state.lastSeen.Unix(),
			})
		}
	}
	e.mu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Score > entries[j].Score
	})
	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// decay reduces all IP scores by decayRate, removing entries that reach 0.
func (e *Engine) decay() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for ip, state := range e.states {
		if state.score <= 0 {
			delete(e.states, ip)
			continue
		}
		reduction := int(float64(state.score) * e.decayRate)
		if reduction < 1 {
			reduction = 1
		}
		state.score -= reduction
		if state.score <= 0 {
			delete(e.states, ip)
		}
	}
}
