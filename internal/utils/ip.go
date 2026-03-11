package utils

import (
	"net"
	"strings"

	"github.com/8w6s/noxis/config"
	"github.com/valyala/fasthttp"
)

// ExtractClientIP parses the request headers based on CGNAT configuration to determine the true Client IP.
// Useful when Noxis Proxy is placed behind a CDN (Cloudflare) or Load Balancer.
func ExtractClientIP(ctx *fasthttp.RequestCtx, cfg *config.AppConfig) string {
	socketIP := ctx.RemoteIP().String()

	if cfg == nil || len(cfg.CGNAT.ExtractHeaders) == 0 {
		return socketIP
	}

	// 1. Validate if the request is coming from a trusted proxy
	isTrusted := false
	if len(cfg.CGNAT.TrustedProxies) == 0 {
		// If no trusted proxies defined, we implicitly trust all headers (dangerous but possible)
		isTrusted = true
	} else {
		for _, trusted := range cfg.CGNAT.TrustedProxies {
			if trusted == socketIP {
				isTrusted = true
				break
			}
			// basic CIDR check
			if strings.Contains(trusted, "/") {
				_, ipnet, err := net.ParseCIDR(trusted)
				if err == nil && ipnet.Contains(ctx.RemoteIP()) {
					isTrusted = true
					break
				}
			}
		}
	}

	if !isTrusted {
		return socketIP
	}

	// 2. Iterate over exact configured headers in priority order
	for _, headerName := range cfg.CGNAT.ExtractHeaders {
		val := string(ctx.Request.Header.Peek(headerName))
		if val != "" {
			// Some proxy headers like X-Forwarded-For can contain multiple IPs separated by comma
			// The syntax is usually: client, proxy1, proxy2
			// We take the first one.
			parts := strings.Split(val, ",")
			firstIP := strings.TrimSpace(parts[0])

			// Validate if it is a valid IP before trusting it entirely
			if net.ParseIP(firstIP) != nil {
				return firstIP
			}
		}
	}

	// Fallback to socket IP if no valid header found
	return socketIP
}

// GetClientIP fetches the previously resolved Real-IP from the context.
// If not found, falls back safely to the socket IP.
func GetClientIP(ctx *fasthttp.RequestCtx) string {
	if val, ok := ctx.UserValue("RealIP").(string); ok && val != "" {
		return val
	}
	return ctx.RemoteIP().String()
}
