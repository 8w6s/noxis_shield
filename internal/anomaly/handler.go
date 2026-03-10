package anomaly

import (
	"github.com/8w6s/noxis/internal/proxy"
	"github.com/valyala/fasthttp"
)

type anomalyHandler struct {
	detector *Detector
}

// NewHandler creates a new proxy handler that logs traffic for anomaly detection.
func NewHandler(detector *Detector) proxy.Handler {
	return &anomalyHandler{detector: detector}
}

func (h *anomalyHandler) Process(ctx *fasthttp.RequestCtx) bool {
	// Simply record the hit for RPS calculations.
	// The detector runs asynchronously and will fire callbacks if standard deviation spikes.
	h.detector.RecordHit()
	return true
}

func (h *anomalyHandler) Name() string {
	return "AnomalyDetector"
}
