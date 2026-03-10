package blocklist

import (
	"context"

	"github.com/8w6s/noxis/internal/proxy"
	"github.com/valyala/fasthttp"
)

type blocklistHandler struct {
	manager *Manager
}

// NewHandler creates a new handler that implements proxy.Handler.
func NewHandler(manager *Manager) proxy.Handler {
	return &blocklistHandler{manager: manager}
}

func (h *blocklistHandler) Process(ctx *fasthttp.RequestCtx) bool {
	// RemoteIP returns the client's IP parsed perfectly by fasthttp
	ip := ctx.RemoteIP().String()

	// 1. Check if the IP is whitelisted
	if h.manager.IsWhitelisted(context.Background(), ip) {
		return true
	}

	// 2. Check if the IP is in the Redis Blocklist
	blocked, _ := h.manager.IsBlocked(context.Background(), ip)
	if blocked {
		// The IP is blocked in Redis but somehow reached the proxy Layer 7.
		// This can happen if the proxy was restarted (so userspace map is empty)
		// but Redis still remembers the bad actor.

		// Re-sync this IP to Shield (Layer 1) to drop subsequent packets faster.
		h.manager.shield.Block(ip)
		h.manager.shield.RecordDrop(ip)

		// Reject this HTTP request right away
		ctx.Error("Forbidden by Noxis", fasthttp.StatusForbidden)
		return false
	}

	// 3. AbuseIPDB check could be dispatched asynchronously right here
	// go func() { checkAbuseIPDB(ip) }()

	return true
}

func (h *blocklistHandler) Name() string {
	return "Blocklist"
}
