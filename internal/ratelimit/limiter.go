package ratelimit

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter manages rolling usage per IP utilizing the Sliding Window Counter algorithm.
// This is an O(1) memory algorithm comparing previous and current fixed windows.
type Limiter struct {
	rdb             *redis.Client
	windowSeconds   int
	maxRequests     int
	subnetThreshold int
	adaptive        bool
}

// New creates a new rate limiter manager.
func New(rdb *redis.Client, windowSec, maxReq, subnetThresh int, adaptive bool) *Limiter {
	return &Limiter{
		rdb:             rdb,
		windowSeconds:   windowSec,
		maxRequests:     maxReq,
		subnetThreshold: subnetThresh,
		adaptive:        adaptive,
	}
}

// slidingWindowScript atomically calculates sliding window rate limit.
// It uses two keys per IP: current_window and previous_window.
var slidingWindowScript = redis.NewScript(`
local current_key = KEYS[1]
local previous_key = KEYS[2]

local max_requests = tonumber(ARGV[1])
local window_size = tonumber(ARGV[2])
local current_time = tonumber(ARGV[3]) -- timestamp in MS
local current_window_start = tonumber(ARGV[4]) -- window boundary in MS

-- Calculate overlap weight (percentage of time spent in the current window)
local time_passed_in_current = current_time - current_window_start
local weight = 1 - (time_passed_in_current / (window_size * 1000))

local prev_count = tonumber(redis.call("GET", previous_key) or "0")
local curr_count = tonumber(redis.call("GET", current_key) or "0")

local estimated_usage = prev_count * weight + curr_count + 1

if estimated_usage > max_requests then
    return 0 -- Blocked
end

-- Update current window count
redis.call("INCR", current_key)
if curr_count == 0 then
    -- Set TTL to span 2 full windows to be safe
    redis.call("EXPIRE", current_key, window_size * 2)
end

return 1 -- Allowed
`)

// subnetIncrScript atomically increments the subnet counter.
var subnetIncrScript = redis.NewScript(`
local key = KEYS[1]
local window_size = tonumber(ARGV[1])
redis.call("INCR", key)
if redis.call("TTL", key) < 0 then
    redis.call("EXPIRE", key, window_size * 2)
end
return redis.call("GET", key)
`)

// extractSubnet24 extracts the /24 subnet string from an IPv4 address.
// Returns empty string for IPv6 or invalid addresses (subnet tracking is IPv4-only for now).
func extractSubnet24(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return "" // IPv6 — skip subnet tracking for now
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

// checkSubnetPressure checks if the /24 subnet is under elevated pressure.
// It does NOT block traffic — it returns a pressure signal for decision making.
// Returns (pressureActive bool, subnetCount int).
func (l *Limiter) checkSubnetPressure(ctx context.Context, ip string, windowStart int64) (bool, int) {
	if l.subnetThreshold <= 0 {
		return false, 0
	}

	subnet := extractSubnet24(ip)
	if subnet == "" {
		return false, 0
	}

	subnetKey := fmt.Sprintf("noxis:subnet:%s:%d", subnet, windowStart)

	// Increment subnet counter (fire-and-forget for hot path performance)
	res, err := subnetIncrScript.Run(ctx, l.rdb,
		[]string{subnetKey},
		l.windowSeconds,
	).Int()

	if err != nil {
		// Fail-open: subnet pressure check is non-critical
		return false, 0
	}

	if res > l.subnetThreshold {
		log.Printf("[RateLimit] Subnet pressure elevated: %s has %d requests in window (threshold: %d)",
			subnet, res, l.subnetThreshold)
		return true, res
	}

	return false, res
}

// Allow checks if the request from the given IP is allowed.
// Returns (allowed bool, subnetUnderPressure bool).
func (l *Limiter) Allow(ctx context.Context, ip string) (bool, bool) {
	// Base limit
	limit := l.maxRequests

	now := time.Now()
	nowMs := now.UnixMilli()
	windowSizeMs := int64(l.windowSeconds * 1000)

	// Determine current window bucket (aligned by timestamp)
	currentWindowStart := (nowMs / windowSizeMs) * windowSizeMs
	prevWindowStart := currentWindowStart - windowSizeMs

	// Adaptive: bump limit by 20% if IP was clean for an hour
	if l.adaptive {
		trustKey := fmt.Sprintf("noxis:trust:%s", ip)
		if l.rdb.Exists(ctx, trustKey).Val() == 1 {
			limit = limit + int(float64(limit)*0.20)
		}
	}

	// Check subnet pressure (non-blocking, runs alongside per-IP check)
	subnetPressure, _ := l.checkSubnetPressure(ctx, ip, currentWindowStart)

	// If subnet is under pressure, apply tighter per-IP limit (50% reduction)
	if subnetPressure {
		tighter := limit / 2
		if tighter < 1 {
			tighter = 1
		}
		limit = tighter
	}

	currentKey := fmt.Sprintf("noxis:rl:%s:%d", ip, currentWindowStart)
	prevKey := fmt.Sprintf("noxis:rl:%s:%d", ip, prevWindowStart)

	res, err := slidingWindowScript.Run(ctx, l.rdb,
		[]string{currentKey, prevKey},
		limit, l.windowSeconds, nowMs, currentWindowStart,
	).Int()

	if err != nil {
		// Log error, but fail open to not block valid traffic
		return true, subnetPressure
	}

	allowed := res == 1
	if !allowed {
		// If blocked, penalize the IP (remove trust status)
		l.rdb.Del(ctx, fmt.Sprintf("noxis:trust:%s", ip))
	} else if l.adaptive {
		// Keep bumping the trust TTL while allowed
		l.rdb.SetEx(ctx, fmt.Sprintf("noxis:trust:%s", ip), "1", time.Hour)
	}

	return allowed, subnetPressure
}
