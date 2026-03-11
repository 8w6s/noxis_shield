package reputation

import (
	"log"
	"time"

	"github.com/8w6s/noxis/internal/proxy"
	"github.com/8w6s/noxis/internal/signals"
	"github.com/8w6s/noxis/internal/utils"
	"github.com/valyala/fasthttp"
)

type reputationHandler struct {
	manager   *Manager
	sigEngine *signals.Engine // unified signal layer
}

// NewHandler creates a middleware pipeline hook for Reputation Scoring.
func NewHandler(manager *Manager, sigEngine *signals.Engine) proxy.Handler {
	return &reputationHandler{
		manager:   manager,
		sigEngine: sigEngine,
	}
}

func (h *reputationHandler) Process(ctx *fasthttp.RequestCtx) bool {
	ip := utils.GetClientIP(ctx)

	// 1. Record the hit and increment behavior score (existing logic preserved)
	isAbusing := h.manager.RecordHit(ip)

	// 2. If the DataBlock threshold is exceeded, emit a critical signal
	// and immediately drop the request. The ScoreEngine handles escalation to blocklist.
	if isAbusing {
		log.Printf("[Reputation] IP %s flagged as abusive (behavior score exceeded threshold)", ip)

		if h.sigEngine != nil {
			h.sigEngine.Emit(signals.Signal{
				IP:       ip,
				Source:   "reputation",
				Reason:   "behavioral abuse score exceeded",
				Severity: signals.SeverityCritical,
				Weight:   signals.WeightReputationCritical,
				Timestamp: time.Now(),
			})
		}

		// Immediate 403 — the ScoreEngine will escalate to full block asynchronously
		ctx.Error("Forbidden", fasthttp.StatusForbidden)
		return false
	}

	return true
}

func (h *reputationHandler) Name() string {
	return "ReputationDataBlock"
}
