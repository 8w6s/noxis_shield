//go:build !linux

package shield

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// userspaceShield implements the Shield interface purely in Go.
// This is the fallback driver used on Windows, macOS, or bare-metal without eBPF.
// It relies on early connection checks (usually in fasthttp.ConnState or a middleware)
// to drop traffic, which is slower than kernel-level but cross-platform.
type userspaceShield struct {
	blockedIPs sync.Map // Concurrent map: ip(string) -> blocked(bool)
	dropCount  atomic.Int64
}

// New creates a new instance of the Userspace shield driver.
func New() Shield {
	log.Println("[Shield] Selected Driver: Go Userspace (Platform-agnostic Fallback)")
	return &userspaceShield{}
}

func (s *userspaceShield) Start() error {
	log.Println("[Shield] Userspace Driver started. Ready to intercept connections.")
	return nil
}

func (s *userspaceShield) Stop() error {
	log.Println("[Shield] Userspace Driver stopped.")
	return nil
}

func (s *userspaceShield) Block(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}
	s.blockedIPs.Store(ip, true)
	return nil
}

func (s *userspaceShield) Unblock(ip string) error {
	s.blockedIPs.Delete(ip)
	return nil
}

func (s *userspaceShield) IsBlocked(ip string) bool {
	_, blocked := s.blockedIPs.Load(ip)
	return blocked
}

// RecordDrop manually increments the drop counter. Must be called when a connection is actually dropped.
func (s *userspaceShield) RecordDrop(ip string) {
	s.dropCount.Add(1)
}

func (s *userspaceShield) GetDropCount() int64 {
	return s.dropCount.Load()
}
