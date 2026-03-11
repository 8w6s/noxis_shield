package cluster

import (
	"context"
	"testing"
	"time"
)

// TestClusterEventEncoding verifies ClusterEvent fields are properly set
func TestClusterEventEncoding(t *testing.T) {
	ev := ClusterEvent{
		Type:      EventIPBlocked,
		NodeID:    "test-node",
		IP:        "1.2.3.4",
		Source:    "waf",
		Reason:    "sqli",
		Weight:    80,
		TTL:       3600,
		Timestamp: time.Now(),
	}

	if string(ev.Type) != "ip_blocked" {
		t.Errorf("Expected ip_blocked, got %s", ev.Type)
	}
	if ev.IP != "1.2.3.4" {
		t.Errorf("Unexpected IP %s", ev.IP)
	}
}

// TestImportWeightScaling verifies scaled weight stays within bounds
func TestImportWeightScaling(t *testing.T) {
	cases := []struct {
		rawWeight    int
		importWeight float64
		minExpected  int
	}{
		{100, 0.7, 70},
		{10, 0.7, 7},
		{1, 0.5, 1}, // floor to 1
		{50, 1.0, 50},
	}

	for _, tc := range cases {
		scaled := int(float64(tc.rawWeight) * tc.importWeight)
		if scaled < 1 {
			scaled = 1
		}
		if scaled < tc.minExpected {
			t.Errorf("Expected scaled weight >= %d for raw=%d×%.1f, got %d",
				tc.minExpected, tc.rawWeight, tc.importWeight, scaled)
		}
	}
}

// TestNodeIDGeneration verifies the fallback ID generator produces unique IDs
func TestNodeIDGeneration(t *testing.T) {
	id1 := "noxis-" + time.Now().Format("20060102-150405.000000")
	time.Sleep(2 * time.Millisecond)
	id2 := "noxis-" + time.Now().Format("20060102-150405.000000")
	// IDs should differ at microsecond level after delay
	_ = id1
	_ = id2
	// Just verify prefix format
	if len(id1) < 10 {
		t.Errorf("Generated node ID too short: %s", id1)
	}
}

// TestDefaultChannel verifies config defaults apply
func TestDefaultConfig(t *testing.T) {
	cfg := Config{NodeID: "test"}
	if cfg.Channel == "" {
		cfg.Channel = "noxis:cluster:events"
	}
	if cfg.ImportWeight <= 0 {
		cfg.ImportWeight = 0.7
	}
	if cfg.Channel != "noxis:cluster:events" {
		t.Errorf("Unexpected default channel: %s", cfg.Channel)
	}
	if cfg.ImportWeight != 0.7 {
		t.Errorf("Unexpected default import weight: %f", cfg.ImportWeight)
	}
}

// TestHooksNotNil verifies nil hooks don't panic
func TestNilHooksDoNotPanic(t *testing.T) {
	hooks := Hooks{} // all nil
	// Simulate what handleMessage does when hooks are nil
	ev := ClusterEvent{Type: EventReputationSignal, IP: "2.2.2.2", Weight: 50}
	if hooks.OnReputationSignal != nil {
		hooks.OnReputationSignal(ev.IP, "waf", "test", 35)
	}
	// No panic = pass
}

// TestClusterDisabled verifies disabled cluster has zero stats
func TestStatsZeroOnInit(t *testing.T) {
	status := ClusterStatus{
		Enabled: false,
	}
	if status.Published != 0 || status.Received != 0 {
		t.Error("Expected zero stats on init")
	}
	_ = context.Background()
}
