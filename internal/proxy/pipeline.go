package proxy

import (
	"log"

	"github.com/8w6s/noxis/internal/metrics"
	"github.com/valyala/fasthttp"
)

// Handler interface that all Noxis filtering modules must implement
type Handler interface {
	// Process inspects the request.
	// Returns true if the request should continue to the next handler/upstream.
	// Returns false if the request should be blocked.
	Process(ctx *fasthttp.RequestCtx) bool

	// Name returns the name of the handler for logging and metrics purposes.
	Name() string
}

// Pipeline chains multiple handlers together before forwarding to upstream
type Pipeline struct {
	handlers   []Handler
	upstreams  *UpstreamManager
	client     *fasthttp.Client
	aggregator *metrics.Aggregator
}

// NewPipeline creates a new proxy pipeline
func NewPipeline(upstreams *UpstreamManager, aggregator *metrics.Aggregator) *Pipeline {
	log.Printf("Initializing proxy pipeline with %d upstreams", upstreams.Count())

	return &Pipeline{
		handlers:   make([]Handler, 0),
		upstreams:  upstreams,
		aggregator: aggregator,
		client: &fasthttp.Client{
			// Optimize for typical web traffic
			ReadBufferSize:  8192,
			WriteBufferSize: 8192,
			MaxConnsPerHost: 1024,
		},
	}
}

// Use adds a handler to the end of the pipeline
func (p *Pipeline) Use(h Handler) {
	log.Printf("Registering handler: %s", h.Name())
	p.handlers = append(p.handlers, h)
}

// ServeHTTP is the main entry point for fasthttp server
func (p *Pipeline) ServeHTTP(ctx *fasthttp.RequestCtx) {
	if p.aggregator != nil {
		p.aggregator.AddActiveConnection()
		defer p.aggregator.RemoveActiveConnection()
		p.aggregator.RecordRequest()
	}

	// 1. Run through all registered handlers (Blocklist -> RateLimit -> WAF -> Anomaly)
	for _, h := range p.handlers {
		if !h.Process(ctx) {
			// Handler rejected the request — Pipeline stops here.
			// Total block counting is ONLY done here, not inside individual handlers.
			// Handlers are responsible for setting the proper HTTP status (e.g., 403, 429)
			// and may emit module-specific events, but NOT call aggregator.RecordBlock().
			if p.aggregator != nil {
				p.aggregator.RecordBlock()
			}
			return
		}
	}

	// 2. If all handlers pass, forward to upstream
	p.proxyRequest(ctx)

	if p.aggregator != nil {
		p.aggregator.RecordPass()
	}
}

// proxyRequest copies the original request, sends it to upstream, and pipes the response back.
// It clones the request before rewriting so the original ctx.Request is never mutated.
// On upstream failure, it attempts one failover to an alternate upstream before returning 502.
func (p *Pipeline) proxyRequest(ctx *fasthttp.RequestCtx) {
	// Clone the request — do NOT mutate ctx.Request directly.
	// This preserves original request semantics for logging/tracing.
	var req fasthttp.Request
	ctx.Request.CopyTo(&req)
	defer fasthttp.ReleaseRequest(&req)

	var resp fasthttp.Response
	defer fasthttp.ReleaseResponse(&resp)

	// Strip hop-by-hop headers that must not be forwarded
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Transfer-Encoding")
	req.Header.Del("Upgrade")

	// Attempt upstream request with one failover retry
	err := p.doUpstreamRequest(&req, &resp)
	if err != nil {
		log.Printf("[Proxy Error] All upstreams unreachable: %v", err)
		ctx.Error("Bad Gateway", fasthttp.StatusBadGateway)
		return
	}

	// Copy response back to client
	resp.Header.Del("Connection")
	resp.CopyTo(&ctx.Response)
}

// doUpstreamRequest attempts to send req to an upstream. On failure, tries one alternate upstream.
func (p *Pipeline) doUpstreamRequest(req *fasthttp.Request, resp *fasthttp.Response) error {
	backendAddr := p.upstreams.GetNext()
	if backendAddr == "" {
		return &noUpstreamError{}
	}

	// Rewrite request URI to point to the backend target
	req.URI().SetScheme("http")
	req.URI().SetHost(backendAddr)

	err := p.client.Do(req, resp)
	if err == nil {
		return nil // Success on first try
	}

	log.Printf("[Proxy] Primary upstream %s failed: %v — trying failover", backendAddr, err)
	p.upstreams.MarkFailure(backendAddr)

	// One failover attempt on alternate upstream
	failoverAddr := p.upstreams.GetNext()
	if failoverAddr == "" || failoverAddr == backendAddr {
		return err // No alternate available
	}

	req.URI().SetHost(failoverAddr)
	if err2 := p.client.Do(req, resp); err2 != nil {
		log.Printf("[Proxy] Failover upstream %s also failed: %v", failoverAddr, err2)
		p.upstreams.MarkFailure(failoverAddr)
		return err2
	}

	log.Printf("[Proxy] Failover succeeded via %s", failoverAddr)
	return nil
}

// noUpstreamError is returned when no upstream backend is configured or available.
type noUpstreamError struct{}

func (e *noUpstreamError) Error() string {
	return "no upstream backends available"
}
