package shield

import (
	"testing"
)

func TestUserspaceBlockFlow(t *testing.T) {
	sh := New(500)
	ip := "192.168.1.1"

	if sh.IsBlocked(ip) {
		t.Errorf("expected IP %s not to be blocked initially", ip)
	}

	err := sh.Block(ip)
	if err != nil {
		t.Fatalf("failed to block IP: %v", err)
	}

	if !sh.IsBlocked(ip) {
		t.Errorf("expected IP %s to be blocked", ip)
	}

	blockedList := sh.ListBlocked()
	if len(blockedList) != 1 || blockedList[0] != ip {
		t.Errorf("expected ListBlocked to return [%s], got %v", ip, blockedList)
	}

	err = sh.Unblock(ip)
	if err != nil {
		t.Fatalf("failed to unblock IP: %v", err)
	}

	if sh.IsBlocked(ip) {
		t.Errorf("expected IP %s not to be blocked after unblock", ip)
	}

	if len(sh.ListBlocked()) != 0 {
		t.Errorf("expected ListBlocked to be empty after unblock")
	}

	// Record Drop test
	if sh.GetDropCount() != 0 {
		t.Errorf("expected 0 drops initially, got %d", sh.GetDropCount())
	}
	sh.RecordDrop(ip)
	if sh.GetDropCount() != 1 {
		t.Errorf("expected 1 drop after manual record, got %d", sh.GetDropCount())
	}
}
