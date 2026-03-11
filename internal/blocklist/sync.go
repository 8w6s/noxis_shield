package blocklist

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/8w6s/noxis/internal/shield"
	"github.com/redis/go-redis/v9"
)

// Reconciler periodically syncs the shield's in-memory blocked-IP set with Redis.
// Redis is the durable source of truth. If an entry expires in Redis (TTL), the
// reconciler removes it from the shield. If an entry exists in Redis but not in
// the shield (e.g., after restart), it re-applies it.
type Reconciler struct {
	rdb      *redis.Client
	sh       shield.Shield
	interval time.Duration

	// Metrics (atomic for lock-free reads from dashboard)
	lastRunAt  atomic.Int64 // Unix timestamp
	totalAdds  atomic.Int64
	totalRemoves atomic.Int64
	running    atomic.Bool
}

// ReconcilerStatus is a snapshot of the reconciler's current state.
type ReconcilerStatus struct {
	Running      bool  `json:"running"`
	LastRunAt    int64 `json:"lastRunAt"`    // Unix timestamp, 0 if never
	TotalAdds    int64 `json:"totalAdds"`
	TotalRemoves int64 `json:"totalRemoves"`
}

// NewReconciler creates a new Reconciler.
// interval controls how often it runs (e.g., 30 * time.Second).
func NewReconciler(rdb *redis.Client, sh shield.Shield, interval time.Duration) *Reconciler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Reconciler{
		rdb:      rdb,
		sh:       sh,
		interval: interval,
	}
}

// Start runs the reconciliation loop in a background goroutine.
// It stops when ctx is cancelled.
func (r *Reconciler) Start(ctx context.Context) {
	r.running.Store(true)
	log.Printf("[Reconciler] Starting blocklist sync worker (interval: %s)", r.interval)

	go func() {
		defer r.running.Store(false)

		// Run immediately on start to restore state after reboot
		r.reconcile(ctx)

		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[Reconciler] Stopped.")
				return
			case <-ticker.C:
				r.reconcile(ctx)
			}
		}
	}()
}

// Status returns a point-in-time snapshot of the reconciler's metrics.
func (r *Reconciler) Status() ReconcilerStatus {
	return ReconcilerStatus{
		Running:      r.running.Load(),
		LastRunAt:    r.lastRunAt.Load(),
		TotalAdds:    r.totalAdds.Load(),
		TotalRemoves: r.totalRemoves.Load(),
	}
}

// reconcile performs one reconciliation pass.
func (r *Reconciler) reconcile(ctx context.Context) {
	// 1. Build expected set from Redis (source of truth)
	expectedSet, err := r.scanRedisBlocks(ctx)
	if err != nil {
		log.Printf("[Reconciler] Redis scan failed, skipping this cycle: %v", err)
		return
	}

	// 2. Get current shield state
	currentSet := make(map[string]struct{})
	for _, ip := range r.sh.ListBlocked() {
		currentSet[ip] = struct{}{}
	}

	adds, removes := 0, 0

	// 3. Add missing entries to shield (in Redis but not in shield)
	for ip := range expectedSet {
		if _, ok := currentSet[ip]; !ok {
			if err := r.sh.Block(ip); err != nil {
				log.Printf("[Reconciler] Failed to re-apply block for %s: %v", ip, err)
			} else {
				adds++
			}
		}
	}

	// 4. Remove stale entries from shield (in shield but not in Redis — TTL expired)
	for ip := range currentSet {
		if _, ok := expectedSet[ip]; !ok {
			if err := r.sh.Unblock(ip); err != nil {
				log.Printf("[Reconciler] Failed to remove stale shield block for %s: %v", ip, err)
			} else {
				removes++
			}
		}
	}

	// 5. Update metrics
	r.lastRunAt.Store(time.Now().Unix())
	if adds > 0 {
		r.totalAdds.Add(int64(adds))
	}
	if removes > 0 {
		r.totalRemoves.Add(int64(removes))
	}

	if adds > 0 || removes > 0 {
		log.Printf("[Reconciler] Sync complete: +%d added, -%d removed from shield", adds, removes)
	}
}

// scanRedisBlocks scans all noxis:block:* keys and returns the set of expected blocked IPs.
func (r *Reconciler) scanRedisBlocks(ctx context.Context) (map[string]struct{}, error) {
	expected := make(map[string]struct{})

	var cursor uint64
	for {
		var keys []string
		var err error
		keys, cursor, err = r.rdb.Scan(ctx, cursor, "noxis:block:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("redis SCAN failed: %w", err)
		}

		for _, key := range keys {
			// Verify the key still has a valid value (not a ghost key)
			raw, err := r.rdb.Get(ctx, key).Bytes()
			if err == redis.Nil {
				continue // Already expired between SCAN and GET — skip
			} else if err != nil {
				continue // Redis error on individual key — skip, not fatal
			}

			// Validate it's a proper block record (not garbage)
			var rec blockRecord
			ip := key[12:] // len("noxis:block:") = 12
			if err := json.Unmarshal(raw, &rec); err != nil {
				// Legacy plain string — still a valid block entry
				if string(raw) != "" {
					expected[ip] = struct{}{}
				}
			} else {
				expected[ip] = struct{}{}
			}
		}

		if cursor == 0 {
			break
		}
	}

	return expected, nil
}
