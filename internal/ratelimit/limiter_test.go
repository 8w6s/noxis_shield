package ratelimit

import (
	"testing"
)

func TestExtractSubnet24_Valid(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"1.2.3.4", "1.2.3.0/24"},
		{"192.168.1.100", "192.168.1.0/24"},
		{"10.0.0.1", "10.0.0.0/24"},
	}

	for _, c := range cases {
		got := extractSubnet24(c.ip)
		if got != c.want {
			t.Errorf("extractSubnet24(%q) = %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestExtractSubnet24_IPv6(t *testing.T) {
	// IPv6 should return empty (not supported in subnet /24 tracking yet)
	got := extractSubnet24("::1")
	if got != "" {
		t.Errorf("expected empty string for IPv6, got %q", got)
	}
}

func TestExtractSubnet24_Invalid(t *testing.T) {
	got := extractSubnet24("notanip")
	if got != "" {
		t.Errorf("expected empty string for invalid IP, got %q", got)
	}
}

func TestExtractSubnet24_Empty(t *testing.T) {
	got := extractSubnet24("")
	if got != "" {
		t.Errorf("expected empty string for empty input, got %q", got)
	}
}
