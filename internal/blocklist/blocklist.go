package blocklist

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/8w6s/noxis/internal/shield"
	"github.com/redis/go-redis/v9"
)

// Manager handles IP blocklist and whitelist operations using Redis data store.
// Redis is the durable source of truth. Shield is the fast enforcement cache.
type Manager struct {
	rdb     *redis.Client
	shield  shield.Shield
	ttl     time.Duration
	OnBlock func(ip string, reason string)
}

// BlockedIP represents the structure returned for the Dashboard
type BlockedIP struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	BlockedAt string `json:"blockedAt"`
	ExpiresAt string `json:"expiresAt"`
	Source    string `json:"source"`
}

// blockRecord is the structured value stored in Redis per blocked IP.
type blockRecord struct {
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blockedAt"`
	Source    string    `json:"source"`
}

// New creates a new Blocklist Manager instance.
func New(rdb *redis.Client, sysShield shield.Shield, ttlHours int) *Manager {
	return &Manager{
		rdb:    rdb,
		shield: sysShield,
		ttl:    time.Duration(ttlHours) * time.Hour,
	}
}

// Block adds an IP to the shield (fast enforcement) then persists to Redis (durable truth).
// If the Redis write fails, the shield block is rolled back to maintain consistency.
//
// Flow (Option A — shield-first with rollback):
//  1. shield.Block(ip)        — fast enforcement, immediate effect
//  2. Redis SET key TTL       — durable source of truth
//  3. If Redis SET fails:     — rollback
//     shield.Unblock(ip)
func (m *Manager) Block(ctx context.Context, ip string, reason string) error {
	return m.BlockWithSource(ctx, ip, reason, "manual")
}

// BlockWithSource is like Block but also records the originating module (e.g., "waf", "ratelimit").
func (m *Manager) BlockWithSource(ctx context.Context, ip string, reason string, source string) error {
	// Step 1: Fast enforcement — block in shield immediately
	if err := m.shield.Block(ip); err != nil {
		return fmt.Errorf("shield block failed: %w", err)
	}

	// Step 2: Persist structured record to Redis with TTL
	record := blockRecord{
		Reason:    reason,
		BlockedAt: time.Now().UTC(),
		Source:    source,
	}
	data, err := json.Marshal(record)
	if err != nil {
		// Rollback: undo shield block if we can't form the record
		_ = m.shield.Unblock(ip)
		return fmt.Errorf("failed to marshal block record: %w", err)
	}

	key := fmt.Sprintf("noxis:block:%s", ip)
	if err := m.rdb.Set(ctx, key, data, m.ttl).Err(); err != nil {
		// Step 3: Rollback — Redis write failed, undo shield block to stay consistent
		_ = m.shield.Unblock(ip)
		return fmt.Errorf("redis set failed (rolled back shield block): %w", err)
	}

	if m.OnBlock != nil {
		go m.OnBlock(ip, reason)
	}

	return nil
}

// Unblock removes an IP from both shield and Redis.
func (m *Manager) Unblock(ctx context.Context, ip string) error {
	// Remove from shield first
	if err := m.shield.Unblock(ip); err != nil {
		return fmt.Errorf("shield unblock failed: %w", err)
	}

	key := fmt.Sprintf("noxis:block:%s", ip)
	if err := m.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis del failed: %w", err)
	}

	// Remove from whitelist if present
	_ = m.rdb.Del(ctx, fmt.Sprintf("noxis:allow:%s", ip))

	return nil
}

// IsBlocked checks if an IP is blocked in Redis. Returns true and the reason if blocked.
func (m *Manager) IsBlocked(ctx context.Context, ip string) (bool, string) {
	key := fmt.Sprintf("noxis:block:%s", ip)

	data, err := m.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return false, ""
	} else if err != nil {
		// Fail open — log but don't block valid traffic on Redis error
		return false, ""
	}

	var record blockRecord
	if err := json.Unmarshal(data, &record); err != nil {
		// Legacy string value — return raw as reason
		return true, string(data)
	}

	return true, record.Reason
}

// Whitelist adds an IP to the permanent whitelist in Redis.
func (m *Manager) Whitelist(ctx context.Context, ip string) error {
	// Ensure it's not in the blocklist first
	_ = m.Unblock(ctx, ip)

	key := fmt.Sprintf("noxis:allow:%s", ip)
	return m.rdb.Set(ctx, key, "1", 0).Err() // 0 TTL = never expire
}

// IsWhitelisted checks if an IP is explicitly allowed.
func (m *Manager) IsWhitelisted(ctx context.Context, ip string) bool {
	key := fmt.Sprintf("noxis:allow:%s", ip)
	_, err := m.rdb.Get(ctx, key).Result()
	return err == nil
}

// List retrieves all blocked IPs from Redis via SCAN (safe for large datasets).
func (m *Manager) List(ctx context.Context) ([]BlockedIP, error) {
	var results []BlockedIP

	var cursor uint64
	match := "noxis:block:*"

	for {
		var keys []string
		var err error
		keys, cursor, err = m.rdb.Scan(ctx, cursor, match, 100).Result()
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			ip := key[12:] // len("noxis:block:") = 12
			raw, err := m.rdb.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}

			ttlDur, _ := m.rdb.TTL(ctx, key).Result()
			expiresAt := time.Now().Add(ttlDur).Format(time.RFC3339)

			var record blockRecord
			entry := BlockedIP{IP: ip, ExpiresAt: expiresAt}

			if err := json.Unmarshal(raw, &record); err != nil {
				// Legacy plain-string value
				entry.Reason = string(raw)
				entry.BlockedAt = "unknown"
				entry.Source = "unknown"
			} else {
				entry.Reason = record.Reason
				entry.BlockedAt = record.BlockedAt.Format(time.RFC3339)
				entry.Source = record.Source
			}

			results = append(results, entry)
		}

		if cursor == 0 {
			break
		}
	}

	return results, nil
}
