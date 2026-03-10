package ratelimit

import (
	"context"
	"log"

	"github.com/8w6s/noxis/internal/proxy"
	"github.com/valyala/fasthttp"
)

type rateLimitHandler struct {
	limiter *Limiter
}

// NewHandler creates a new proxy handler for rate limiting.
func NewHandler(limiter *Limiter) proxy.Handler {
	return &rateLimitHandler{limiter: limiter}
}

func (h *rateLimitHandler) Process(ctx *fasthttp.RequestCtx) bool {
	ip := ctx.RemoteIP().String()

	allowed := h.limiter.Allow(context.Background(), ip)
	if !allowed {
		log.Printf("[RateLimit] IP %s exceeded limit and was blocked.", ip)
		ctx.Error("Too Many Requests", fasthttp.StatusTooManyRequests)
		return false
	}

	return true
}

func (h *rateLimitHandler) Name() string {
	return "RateLimit"
}
