package proxy

import (
	"log"

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
	handlers []Handler
	upstream string
	client   *fasthttp.HostClient
}

// NewPipeline creates a new proxy pipeline
func NewPipeline(upstream string) *Pipeline {
	log.Printf("Initializing proxy pipeline for upstream: %s", upstream)
	return &Pipeline{
		handlers: make([]Handler, 0),
		upstream: upstream,
		client: &fasthttp.HostClient{
			Addr: upstream,
			// Optimize for typical web traffic
			ReadBufferSize:  8192,
			WriteBufferSize: 8192,
			MaxConns:        1024,
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
	// 1. Run through all registered handlers (Blocklist -> RateLimit -> Anomaly)
	for _, h := range p.handlers {
		if !h.Process(ctx) {
			// Handler rejected the request, Pipeline stops immediately.
			// Handlers are responsible for setting the proper HTTP status (e.g., 403, 429).
			return
		}
	}

	// 2. If all handlers pass, forward to upstream
	p.proxyRequest(ctx)
}

// proxyRequest copies the original request, sends it to upstream, and pipes the response back
func (p *Pipeline) proxyRequest(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	resp := &ctx.Response

	// Prepare request for forwarding
	// Remove connection related headers and set correct Host
	req.Header.Del("Connection")

	// FastHTTP HostClient handles the connection pool to the upstream Addr
	err := p.client.Do(req, resp)

	if err != nil {
		log.Printf("[Proxy Error] Upstream unreachable: %v", err)
		ctx.Error("Bad Gateway", fasthttp.StatusBadGateway)
		return
	}

	// Cleanup response headers before sending back to client
	resp.Header.Del("Connection")
}
