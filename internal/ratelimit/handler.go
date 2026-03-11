package ratelimit

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/8w6s/noxis/internal/signals"
	"github.com/8w6s/noxis/internal/utils"
	"github.com/valyala/fasthttp"
)

// Ensure rateLimitHandler satisfies proxy.Handler at compile time.
// (proxy import kept via pipeline.Use call in main.go)

type rateLimitHandler struct {
	limiter   *Limiter
	sigEngine *signals.Engine
}

// NewHandler creates a new proxy handler for rate limiting.
// Returns *rateLimitHandler (implements proxy.Handler) to allow chaining WithSignals().
func NewHandler(limiter *Limiter) *rateLimitHandler {
	return &rateLimitHandler{limiter: limiter}
}

// WithSignals attaches the unified signal engine to the rate limit handler.
func (h *rateLimitHandler) WithSignals(e *signals.Engine) *rateLimitHandler {
	h.sigEngine = e
	return h
}

// WithSignals attaches the unified signal engine to the rate limit handler.
func (h *rateLimitHandler) Process(ctx *fasthttp.RequestCtx) bool {
	ip := utils.GetClientIP(ctx)
	now := time.Now()

	allowed, subnetPressure := h.limiter.Allow(context.Background(), ip)

	if subnetPressure && h.sigEngine != nil {
		h.sigEngine.Emit(signals.Signal{
			IP:        ip,
			Source:    "ratelimit",
			Reason:    fmt.Sprintf("subnet /24 pressure"),
			Severity:  signals.SeverityLow,
			Weight:    signals.WeightSubnetPressure,
			Timestamp: now,
		})
	}

	if !allowed {
		log.Printf("[RateLimit] IP %s exceeded rate limit", ip)

		// Emit signal for escalation
		if h.sigEngine != nil {
			h.sigEngine.Emit(signals.Signal{
				IP:        ip,
				Source:    "ratelimit",
				Reason:    "rate limit violation",
				Severity:  signals.SeverityMedium,
				Weight:    signals.WeightRateLimitViolation,
				Timestamp: now,
			})
		}

		ctx.Error("Too Many Requests", fasthttp.StatusTooManyRequests)
		return false
	}

	return true
}

func (h *rateLimitHandler) Name() string {
	return "RateLimit"
}
