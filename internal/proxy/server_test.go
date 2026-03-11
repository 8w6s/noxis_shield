package proxy

import (
	"net"
	"testing"
)

func TestExtractIP_TCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	got := extractIP(addr)
	if got != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", got)
	}
}

func TestExtractIP_NilAddr(t *testing.T) {
	got := extractIP(nil)
	if got != "" {
		t.Errorf("expected empty string for nil addr, got %s", got)
	}
}

func TestExtractIP_UDPAddr(t *testing.T) {
	// Non-TCPAddr fallback path — must not panic
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999}
	got := extractIP(addr)
	if got != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", got)
	}
}

func TestExtractIP_IPv6TCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 8080}
	got := extractIP(addr)
	if got != "::1" {
		t.Errorf("expected ::1, got %s", got)
	}
}
