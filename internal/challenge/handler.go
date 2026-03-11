package challenge

import (
	"time"

	"github.com/8w6s/noxis/internal/proxy"
	"github.com/8w6s/noxis/internal/signals"
	"github.com/8w6s/noxis/internal/utils"
	"github.com/valyala/fasthttp"
)

type challengeHandler struct {
	manager   *Manager
	sigEngine *signals.Engine
}

// NewHandler creates a middleware pipeline hook for JS Proof of Work.
// sigEngine is the unified signal engine (required for score-based challenge decisions).
func NewHandler(manager *Manager, sigEngine *signals.Engine) proxy.Handler {
	return &challengeHandler{
		manager:   manager,
		sigEngine: sigEngine,
	}
}

func (h *challengeHandler) Process(ctx *fasthttp.RequestCtx) bool {
	if !h.manager.cfg.Protection.Challenge.Enabled {
		return true // Skip if disabled
	}

	ip := utils.GetClientIP(ctx)

	// Use unified signal engine score to decide if challenge is needed.
	// Falls back to 0 if engine not wired (safe default = no challenge).
	score := 0
	if h.sigEngine != nil {
		score = h.sigEngine.GetScore(ip)
	}

	// If score is below challenge threshold, pass immediately
	if score < h.manager.cfg.Protection.Challenge.ScoreThreshold {
		return true
	}

	// 1. Is this a POST request answering the challenge?
	if ctx.IsPost() && len(ctx.FormValue("nonce")) > 0 {
		solved := h.manager.HandleVerification(ctx)
		if solved {
			// Reward: reduce score for solving the challenge correctly
			if h.sigEngine != nil {
				h.sigEngine.Emit(signals.Signal{
					IP:        ip,
					Source:    "challenge",
					Reason:    "challenge solved",
					Severity:  signals.SeverityLow,
					Weight:    signals.WeightChallengePass, // negative weight
					Timestamp: time.Now(),
				})
			}
			return true
		}
		// Wrong answer — emit fail signal
		if h.sigEngine != nil {
			h.sigEngine.Emit(signals.Signal{
				IP:        ip,
				Source:    "challenge",
				Reason:    "challenge failed (tampered/wrong nonce)",
				Severity:  signals.SeverityHigh,
				Weight:    signals.WeightChallengeFail,
				Timestamp: time.Now(),
			})
		}
		return false
	}

	// 2. Check if client already solved a challenge recently (valid cookie)
	if h.manager.VerifyProof(ctx) {
		return true // Proven human — let through
	}

	// 3. Serve the JS Challenge page
	h.manager.ServeChallenge(ctx)
	return false // Stop pipeline, challenge HTML is written
}

func (h *challengeHandler) Name() string {
	return "JS_PoW_Challenge"
}
