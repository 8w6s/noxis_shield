package blocklist

import (
	"context"
	"fmt"
	"time"

	"github.com/8w6s/noxis/internal/shield"
	"github.com/redis/go-redis/v9"
)

// Manager handles IP blocklist and whitelist operations using Redis data store.
type Manager struct {
	rdb    *redis.Client
	shield shield.Shield
	ttl    time.Duration
}

// BlockedIP represents the structure returned for the Dashboard
type BlockedIP struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	BlockedAt string `json:"blockedAt"`
	ExpiresAt string `json:"expiresAt"`
}

// New creates a new Blocklist Manager instance.
func New(rdb *redis.Client, sysShield shield.Shield, ttlHours int) *Manager {
	return &Manager{
		rdb:    rdb,
		shield: sysShield,
		ttl:    time.Duration(ttlHours) * time.Hour,
	}
}

// Block adds an IP to the Redis blocklist and syncs it to the Shield Layer 1.
func (m *Manager) Block(ctx context.Context, ip string, reason string) error {
	// First block at Layer 1 immediately
	if err := m.shield.Block(ip); err != nil {
		return fmt.Errorf("shield block failed: %w", err)
	}

	key := fmt.Sprintf("noxis:block:%s", ip)

	// Save to Redis with TTL
	// Value format could just be the reason string, or JSON if we need timestamps.
	// For simplicity, we just store the reason.
	err := m.rdb.Set(ctx, key, reason, m.ttl).Err()
	if err != nil {
		return fmt.Errorf("redis set failed: %w", err)
	}

	return nil
}

// Unblock removes an IP from both Redis and the Shield Layer 1.
func (m *Manager) Unblock(ctx context.Context, ip string) error {
	// Remove from Layer 1
	if err := m.shield.Unblock(ip); err != nil {
		return fmt.Errorf("shield unblock failed: %w", err)
	}

	key := fmt.Sprintf("noxis:block:%s", ip)
	if err := m.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis del failed: %w", err)
	}

	// Remove from whitelist if present just in case
	m.rdb.Del(ctx, fmt.Sprintf("noxis:allow:%s", ip))

	return nil
}

// IsBlocked checks if an IP is blocked in Redis. Returns true and the reason if blocked.
func (m *Manager) IsBlocked(ctx context.Context, ip string) (bool, string) {
	key := fmt.Sprintf("noxis:block:%s", ip)

	reason, err := m.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, ""
	} else if err != nil {
		// Log error, but fail open
		return false, ""
	}

	return true, reason
}

// Whitelist adds an IP to the permanent whitelist in Redis.
func (m *Manager) Whitelist(ctx context.Context, ip string) error {
	// Ensure it's not in the blocklist
	m.Unblock(ctx, ip)

	key := fmt.Sprintf("noxis:allow:%s", ip)
	return m.rdb.Set(ctx, key, "1", 0).Err() // 0 TTL = never expire
}

// IsWhitelisted checks if an IP is explicitly allowed.
func (m *Manager) IsWhitelisted(ctx context.Context, ip string) bool {
	key := fmt.Sprintf("noxis:allow:%s", ip)

	_, err := m.rdb.Get(ctx, key).Result()
	return err == nil
}

// List retrieves all blocked IPs from Redis. Scanning keys is a blocking operation,
// we should ideally use SCAN if the dataset is large.
func (m *Manager) List(ctx context.Context) ([]BlockedIP, error) {
	var results []BlockedIP

	// WARNING: In high-scale prod, avoid KEYS. Use SCAN instead.
	// We use SCAN here appropriately.
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
			reason, _ := m.rdb.Get(ctx, key).Result()
			ttl, _ := m.rdb.TTL(ctx, key).Result()

			expiresAt := time.Now().Add(ttl).Format(time.RFC3339)
			blockedAt := time.Now().Add(ttl - m.ttl).Format(time.RFC3339) // approximate if we don't store the exact time

			results = append(results, BlockedIP{
				IP:        ip,
				Reason:    reason,
				BlockedAt: blockedAt,
				ExpiresAt: expiresAt,
			})
		}

		if cursor == 0 {
			break
		}
	}

	return results, nil
}
