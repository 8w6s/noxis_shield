package defense

import (
	"sync"
	"time"
)

// Mode represents the current operational defense state of the proxy.
type Mode string

const (
	ModeNormal      Mode = "normal"
	ModeElevated    Mode = "elevated"
	ModeUnderAttack Mode = "under_attack"
	ModeRecovery    Mode = "recovery"
)

// Manager holds the global defense state.
type Manager struct {
	mu           sync.RWMutex
	currentMode  Mode
	modeChangedAt time.Time

	// Callbacks
	OnModeChanged func(oldMode, newMode Mode, reason string)
}

// NewManager creates a new defense manager starting in normal mode.
func NewManager() *Manager {
	return &Manager{
		currentMode:   ModeNormal,
		modeChangedAt: time.Now(),
	}
}

// SetMode changes the current defense mode and fires the callback if it changed.
func (m *Manager) SetMode(newMode Mode, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentMode == newMode {
		return
	}

	oldMode := m.currentMode
	m.currentMode = newMode
	m.modeChangedAt = time.Now()

	if m.OnModeChanged != nil {
		go m.OnModeChanged(oldMode, newMode, reason)
	}
}

// GetMode returns the current active defense mode.
func (m *Manager) GetMode() Mode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentMode
}

// GetState returns the current mode and how long it has been active.
func (m *Manager) GetState() (Mode, time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentMode, time.Since(m.modeChangedAt)
}
