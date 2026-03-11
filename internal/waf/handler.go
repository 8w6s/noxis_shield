package waf

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/8w6s/noxis/internal/metrics"
	"github.com/8w6s/noxis/internal/signals"
	"github.com/8w6s/noxis/internal/utils"
	"github.com/valyala/fasthttp"
)

// Handler integrates the OWASP WAF Engine into the proxy pipeline.
type Handler struct {
	engine     *Engine
	aggregator *metrics.Aggregator
	sigEngine  *signals.Engine // unified signal layer (optional)
	runtimeOn  *atomic.Bool    // runtime toggle from admin API
}

// NewHandler creates a new WAF middleware handler.
func NewHandler(engine *Engine, aggregator *metrics.Aggregator, runtimeOn *atomic.Bool) *Handler {
	return &Handler{
		engine:     engine,
		aggregator: aggregator,
		runtimeOn:  runtimeOn,
	}
}

// WithSignals attaches the unified signal engine to the WAF handler.
func (h *Handler) WithSignals(e *signals.Engine) *Handler {
	h.sigEngine = e
	return h
}

// Name returns the identifier of the middleware
func (h *Handler) Name() string {
	return "waf"
}

// Process inspects the incoming request using the WAF engine.
func (h *Handler) Process(ctx *fasthttp.RequestCtx) bool {
	// First check the dynamic runtime toggle
	if h.runtimeOn != nil && !h.runtimeOn.Load() {
		return true // Allow, WAF disabled via Dashboard
	}

	// Fallback to static config if runtime toggle is missing/on
	if !h.engine.cfg.WAF.Enabled {
		return true // Allow
	}

	result := h.engine.Inspect(ctx)

	if result.Blocked {
		ip := utils.GetClientIP(ctx)
		log.Printf("[WAF] Request blocked from %s. Rule ID: %s, Score: %d, Severity: %s",
			ip, result.TopRule, result.Score, result.TopRuleSeverity)

		// Emit module-specific WAF event — block counting centralized in Pipeline.
		if h.aggregator != nil {
			h.aggregator.AddEvent("waf_blocked",
				fmt.Sprintf("IP %s triggered Rule %s (score: %d, severity: %s)",
					ip, result.TopRule, result.Score, result.TopRuleSeverity))
		}

		// Emit unified signal for escalation
		if h.sigEngine != nil {
			sev := mapWAFSeverity(result.TopRuleSeverity)
			h.sigEngine.Emit(signals.Signal{
				IP:       ip,
				Source:   "waf",
				Reason:   fmt.Sprintf("rule:%s score:%d", result.TopRule, result.Score),
				Severity: sev,
				Weight:   signals.SeverityWeight(sev),
				Meta:     map[string]string{"rule_id": result.TopRule},
				Timestamp: time.Now(),
			})
		}

		ctx.Response.SetStatusCode(fasthttp.StatusForbidden)
		ctx.Response.SetBodyString("Noxis WAF: Access Denied. Malicious signature detected.\n")
		return false // Block and stop chain
	}

	return true // Allow
}

// mapWAFSeverity converts a WAF rule severity string to signals.Severity.
func mapWAFSeverity(severity string) signals.Severity {
	switch severity {
	case "critical":
		return signals.SeverityCritical
	case "high":
		return signals.SeverityHigh
	case "low":
		return signals.SeverityLow
	default:
		return signals.SeverityMedium
	}
}
