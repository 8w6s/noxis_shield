package shield

// Shield is the common interface for platform-agnostic L3/L4 blocking.
// On Linux, this will be implemented via eBPF/XDP.
// On Windows/macOS, this will fallback to a concurrent userspace map.
type Shield interface {
	// Block adds an IP address to the blocklist.
	Block(ip string) error

	// Unblock removes an IP address from the blocklist.
	Unblock(ip string) error

	// IsBlocked checks if an IP is currently blocked by the shield.
	IsBlocked(ip string) bool

	// RecordDrop manually records a dropped connection.
	RecordDrop(ip string)

	// GetDropCount returns the total number of packets/connections dropped by the shield.
	GetDropCount() int64

	// Start initializes the shield (e.g., loads eBPF program or starts userspace listener).
	Start() error

	// Stop cleanly shuts down the shield and cleans up resources.
	Stop() error
}
