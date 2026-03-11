package signals

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestEngineAccumulation(t *testing.T) {
	eng := NewEngine(EscalationConfig{})
	ip := "192.168.1.1"

	eng.Emit(Signal{IP: ip, Weight: 10, Source: "waf"})
	if eng.GetScore(ip) != 10 {
		t.Errorf("expected score 10, got %d", eng.GetScore(ip))
	}

	eng.Emit(Signal{IP: ip, Weight: 20, Source: "waf"})
	if eng.GetScore(ip) != 30 {
		t.Errorf("expected score 30, got %d", eng.GetScore(ip))
	}

	// Reward
	eng.Emit(Signal{IP: ip, Weight: -5, Source: "challenge"})
	if eng.GetScore(ip) != 25 {
		t.Errorf("expected score 25 after reward, got %d", eng.GetScore(ip))
	}
}

func TestEngineDecay(t *testing.T) {
	// Set high BlockThreshold so the 100-weight signal doesn't trigger block & reset score
	eng := NewEngine(EscalationConfig{
		BlockThreshold: 200,
	})
	ip := "10.0.0.1"
	
	eng.Emit(Signal{IP: ip, Weight: 100, Source: "test"})
	eng.decay() // Manual trigger

	// 10% of 100 is 10. Remaining: 90
	if eng.GetScore(ip) != 90 {
		t.Errorf("expected score 90 after decay, got %d", eng.GetScore(ip))
	}

	eng.Emit(Signal{IP: "10.0.0.2", Weight: 5, Source: "test"})
	eng.decay() 
	// 10% of 5 is 0.5 -> floored to 0? No, reduction < 1 sets reduction=1. Remaining: 4
	if eng.GetScore("10.0.0.2") != 4 {
		t.Errorf("expected score 4 after decay(reduction=1 fallback), got %d", eng.GetScore("10.0.0.2"))
	}
}

func TestEngineThresholds(t *testing.T) {
	var challenges int32
	var blocks int32

	eng := NewEngine(EscalationConfig{
		ChallengeThreshold: 20,
		ElevatedThreshold:  0,
		BlockThreshold:     50,
		OnChallenge: func(ip string) {
			atomic.AddInt32(&challenges, 1)
		},
		OnBlock: func(ip, reason string) {
			atomic.AddInt32(&blocks, 1)
		},
	})
	ip := "1.1.1.1"

	eng.Emit(Signal{IP: ip, Weight: 15})
	if atomic.LoadInt32(&challenges) != 0 {
		t.Error("challenge callback fired prematurely")
	}

	eng.Emit(Signal{IP: ip, Weight: 10}) // Score now 25
	time.Sleep(10 * time.Millisecond) // Give goroutine time
	if atomic.LoadInt32(&challenges) != 1 {
		t.Error("challenge callback should have fired exactly once")
	}

	eng.Emit(Signal{IP: ip, Weight: 10}) // Score now 35
	time.Sleep(10 * time.Millisecond)
	if atomic.LoadInt32(&challenges) != 1 {
		t.Error("challenge callback should NOT fire again")
	}

	eng.Emit(Signal{IP: ip, Weight: 20}) // Score now 55 -> Block!
	time.Sleep(10 * time.Millisecond)
	if atomic.LoadInt32(&blocks) != 1 {
		t.Error("block callback should have fired")
	}

	// Score should be reset after block
	if eng.GetScore(ip) != 0 {
		t.Errorf("expected score 0 after block reset, got %d", eng.GetScore(ip))
	}
}

func TestEngineWhitelist(t *testing.T) {
	var blocks int32
	eng := NewEngine(EscalationConfig{
		BlockThreshold: 50,
		OnBlock: func(ip, reason string) {
			atomic.AddInt32(&blocks, 1)
		},
	})

	ip := "8.8.8.8"
	eng.Bypass(ip)

	eng.Emit(Signal{IP: ip, Weight: 100})
	time.Sleep(10 * time.Millisecond)

	if atomic.LoadInt32(&blocks) != 0 {
		t.Error("block callback fired for whitelisted IP")
	}

	// Score is still tracked
	if eng.GetScore(ip) != 100 {
		t.Errorf("expected whitelist IP to still accumulate score 100, got %d", eng.GetScore(ip))
	}
}

func TestEngineTopOffenders(t *testing.T) {
	eng := NewEngine(EscalationConfig{})
	eng.Emit(Signal{IP: "1.1.1.1", Weight: 10})
	eng.Emit(Signal{IP: "2.2.2.2", Weight: 50})
	eng.Emit(Signal{IP: "3.3.3.3", Weight: 30})

	top := eng.GetTopOffenders(2)
	if len(top) != 2 {
		t.Fatalf("expected 2 offenders, got %d", len(top))
	}

	if top[0].IP != "2.2.2.2" || top[0].Score != 50 {
		t.Errorf("expected #1 to be 2.2.2.2 (50), got %s (%d)", top[0].IP, top[0].Score)
	}
	if top[1].IP != "3.3.3.3" || top[1].Score != 30 {
		t.Errorf("expected #2 to be 3.3.3.3 (30), got %s (%d)", top[1].IP, top[1].Score)
	}
}
