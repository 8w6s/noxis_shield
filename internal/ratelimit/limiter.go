package ratelimit

import (
	"context"
	"fmt"
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

// Allow checks if the request from the given IP is allowed.
// Returns true if allowed, false if rate limited.
func (l *Limiter) Allow(ctx context.Context, ip string) bool {
	// Base values
	limit := l.maxRequests

	// Adaptive: bump limit by 20% if IP was clean for an hour
	if l.adaptive {
		trustKey := fmt.Sprintf("noxis:trust:%s", ip)
		if l.rdb.Exists(ctx, trustKey).Val() == 1 {
			limit = limit + int(float64(limit)*0.20)
		}
	}

	now := time.Now()
	nowMs := now.UnixMilli()
	windowSizeMs := int64(l.windowSeconds * 1000)

	// Determine current window bucket (aligned by timestamp)
	currentWindowStart := (nowMs / windowSizeMs) * windowSizeMs
	prevWindowStart := currentWindowStart - windowSizeMs

	currentKey := fmt.Sprintf("noxis:rl:%s:%d", ip, currentWindowStart)
	prevKey := fmt.Sprintf("noxis:rl:%s:%d", ip, prevWindowStart)

	res, err := slidingWindowScript.Run(ctx, l.rdb,
		[]string{currentKey, prevKey},
		limit, l.windowSeconds, nowMs, currentWindowStart,
	).Int()

	if err != nil {
		// Log error, but fail open to not block valid traffic
		return true
	}

	allowed := res == 1
	if !allowed {
		// If blocked, penalize the IP (remove trust status)
		l.rdb.Del(ctx, fmt.Sprintf("noxis:trust:%s", ip))
	} else if l.adaptive {
		// Keep bumping the trust TTL while allowed
		l.rdb.SetEx(ctx, fmt.Sprintf("noxis:trust:%s", ip), "1", time.Hour)
	}

	return allowed
}
