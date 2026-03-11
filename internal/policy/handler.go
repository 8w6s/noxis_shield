package policy

import (
	"fmt"
	"log"

	"github.com/8w6s/noxis/internal/challenge"
	"github.com/8w6s/noxis/internal/metrics"
	"github.com/8w6s/noxis/internal/signals"
	"github.com/8w6s/noxis/internal/utils"
	"github.com/valyala/fasthttp"
)

// Handler connects the Policy Engine into the main HTTP pipeline.
type Handler struct {
	engine     *Engine
	aggregator *metrics.Aggregator
	sigEngine  *signals.Engine
	chalMgr    *challenge.Manager
}

// NewHandler creates a new handler wrapping the Policy Engine
func NewHandler(engine *Engine, aggr *metrics.Aggregator, chalMgr *challenge.Manager) *Handler {
	return &Handler{
		engine:     engine,
		aggregator: aggr,
		chalMgr:    chalMgr,
	}
}

// WithSignals injects the unified signal engine
func (h *Handler) WithSignals(sigEngine *signals.Engine) *Handler {
	h.sigEngine = sigEngine
	return h
}

// Name returns the handler identifier for logging
func (h *Handler) Name() string {
	return "policy"
}

// Process is called by the proxy pipeline for every request.
// It implements the proxy.Handler interface.
func (h *Handler) Process(ctx *fasthttp.RequestCtx) bool {
	matchedRule := h.engine.Evaluate(ctx)
	if matchedRule == nil {
		return true // Pass to next handler
	}

	ip := utils.GetClientIP(ctx)
	action := matchedRule.Action

	// Emit signal if rule specifies a threat severity
	if matchedRule.Severity > 0 && h.sigEngine != nil {
		h.sigEngine.Emit(signals.Signal{
			IP:     ip,
			Source: "policy",
			Weight: matchedRule.Severity,
			Reason: fmt.Sprintf("Matched Rule: %s", matchedRule.Name),
		})
	}

	switch action {
	case ActionBlock:
		log.Printf("[Policy] BLOCK triggered by rule '%s' from IP %s", matchedRule.Name, ip)
		h.aggregator.AddEvent("policy_block", fmt.Sprintf("Rule '%s' triggered by %s", matchedRule.Name, ip))

		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetBodyString("Access Denied by Noxis Policy Engine")
		return false // Short-circuit proxy

	case ActionChallenge:
		log.Printf("[Policy] CHALLENGE triggered by rule '%s' from IP %s", matchedRule.Name, ip)
		if h.chalMgr != nil {
			if h.chalMgr.VerifyProof(ctx) {
				return true // They have a valid PoW cookie - let them through
			}
			h.chalMgr.ServeChallenge(ctx)
			return false
		}
		// Fallback to Block if challenge manager not configured
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetBodyString("Access Denied (Challenge Fallback)")
		return false

	case ActionLog:
		log.Printf("[Policy] LOG matched rule '%s' for IP %s", matchedRule.Name, ip)
		return true // Let it pass through

	default:
		return true // Unknown action defaults to fail-open
	}
}
