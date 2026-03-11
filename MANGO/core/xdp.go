package core

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"mango-waf/logger"
)

// XDPManager provides a high-performance eBPF/XDP mapping interface for hardware-level dropping
type XDPManager struct {
	Enabled       bool
	MapName       string
	BPFToolBinary string
}

func NewXDPManager() *XDPManager {
	x := &XDPManager{
		MapName: "blacklist",
	}

	// 1. Must be root to mess with eBPF maps
	currentUser, err := user.Current()
	if err != nil || currentUser.Uid != "0" {
		logger.Warn("XDP requires root privileges. XDP hardware dropping disabled.")
		return x
	}

	// 2. Discover bpftool
	path, err := exec.LookPath("bpftool")
	if err != nil {
		path = "/usr/sbin/bpftool" // fallback
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Warn("bpftool not found. XDP hardware dropping disabled. Please install 'linux-tools-common' or 'bpftool'")
		return x
	}
	x.BPFToolBinary = path

	// 3. Verify that the BPF Map actually exists (Meaning XDP is attached to the card)
	cmd := exec.Command(x.BPFToolBinary, "map", "show", "name", x.MapName)
	if err := cmd.Run(); err != nil {
		logger.Warn("XDP map 'blacklist' not found. Ensure xdp_mango run successfully on NIC.", "error", err.Error())
		return x
	}

	x.Enabled = true
	logger.Info("XDP eBPF Hardware Dropping Enabled. 10M RPS mode ready.")
	return x
}

// BanIP pushes the banned IP address securely down to the NIC driver layer
func (x *XDPManager) BanIP(ipAddr string) error {
	if !x.Enabled {
		return nil
	}

	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil {
		return fmt.Errorf("invalid ip")
	}

	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("XDP currently supports IPv4 only") // Map key size is 4 bytes
	}

	// For BPF mapping, the key format via bpftool requires hex space separated
	// IPv4 "103.77.246.12" -> hex 67 4d f6 0c
	hexIP := fmt.Sprintf("hex %02x %02x %02x %02x", ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	// Value is a 64-bit uint counter initially set to 0. 8 bytes long.
	hexVal := "hex 00 00 00 00 00 00 00 00"

	// Using exec with strings split correctly to avoid shell injections
	args := []string{"map", "update", "name", x.MapName, "key"}
	args = append(args, strings.Split(hexIP, " ")...)
	args = append(args, "value")
	args = append(args, strings.Split(hexVal, " ")...)

	cmd := exec.Command(x.BPFToolBinary, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update bpf map: %v", err)
	}
	return nil
}

// UnbanIP removes the IP address from the Hardware NIC drop list
func (x *XDPManager) UnbanIP(ipAddr string) error {
	if !x.Enabled {
		return nil
	}

	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil || parsedIP.To4() == nil {
		return nil
	}
	ipv4 := parsedIP.To4()
	hexIP := fmt.Sprintf("hex %02x %02x %02x %02x", ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	args := []string{"map", "delete", "name", x.MapName, "key"}
	args = append(args, strings.Split(hexIP, " ")...)

	cmd := exec.Command(x.BPFToolBinary, args...)
	return cmd.Run()
}

// GetStats returns the number of IPs currently in the hardware blacklist and total packets dropped
func (x *XDPManager) GetStats() (int64, int64) {
	if !x.Enabled {
		return 0, 0
	}

	// Capture 'bpftool -j map dump' to count entries and sum values
	cmd := exec.Command(x.BPFToolBinary, "-j", "map", "dump", "name", x.MapName)
	out, err := cmd.Output()
	if err != nil {
		return 0, 0
	}

	type BPFEntry struct {
		Key   []string `json:"key"`
		Value []string `json:"value"`
	}
	var entries []BPFEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return 0, 0
	}

	var totalDrops int64
	for _, e := range entries {
		// Value is 8 bytes in big-endian or little-endian depending on kernel
		// but typically it represents a __u64 counter.
		// For simplicity, we just parse the bytes.
		if len(e.Value) == 8 {
			var val uint64
			for i := 0; i < 8; i++ {
				var b byte
				fmt.Sscanf(e.Value[i], "0x%x", &b)
				val |= uint64(b) << (i * 8) // Little endian
			}
			totalDrops += int64(val)
		}
	}

	return int64(len(entries)), totalDrops
}
