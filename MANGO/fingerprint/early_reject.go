package fingerprint

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"mango-waf/logger"
)

// EarlyRejectStats tracks statistics for raw TCP-level rejection
type EarlyRejectStats struct {
	TotalProcessed int64
	TotalRejected  int64
	LastError      string
}

var globalEarlyRejectStats EarlyRejectStats

// GetEarlyRejectStats returns current statistics
func GetEarlyRejectStats() (int64, int64) {
	return atomic.LoadInt64(&globalEarlyRejectStats.TotalProcessed),
		atomic.LoadInt64(&globalEarlyRejectStats.TotalRejected)
}

// SniffingListener wraps a net.Listener to perform early TLS fingerprint analysis
type SniffingListener struct {
	net.Listener
	Store         *FingerprintStore
	RejectLow     bool // Whether to reject low-trust fingerprints immediately
	IsUnderAttack func() bool
}

// NewSniffingListener creates a listener that performs early TLS sniffing
func NewSniffingListener(inner net.Listener, store *FingerprintStore, isUnderAttack func() bool) *SniffingListener {
	return &SniffingListener{
		Listener:      inner,
		Store:         store,
		RejectLow:     true,
		IsUnderAttack: isUnderAttack,
	}
}

// Accept implements net.Listener.Accept
func (l *SniffingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&globalEarlyRejectStats.TotalProcessed, 1)

	// Wrap connection to sniff first few bytes
	return l.sniff(conn)
}

func (l *SniffingListener) sniff(conn net.Conn) (net.Conn, error) {
	// Set a short deadline for sniffing to prevent hanging connections
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	// Use a peek-capable reader (custom implementation to avoid large allocations)
	br := bufio.NewReaderSize(conn, 1024)

	// Peek at the first few bytes (TLS Record Header: 5 bytes)
	header, err := br.Peek(5)
	if err != nil {
		// If we can't even read 5 bytes, it might not be a valid connection
		conn.SetReadDeadline(time.Time{})
		return &BufferedConn{Conn: conn, Reader: br}, nil
	}

	// Reset deadline
	conn.SetReadDeadline(time.Time{})

	// Check if it's a TLS Handshake (0x16)
	if header[0] != 0x16 {
		return &BufferedConn{Conn: conn, Reader: br}, nil
	}

	// Expected length of the handshake record
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 0 && recordLen < 16384 {
		// Peek at the body (recordLen + 5 header bytes)
		// We limit our peek to 2KB to avoid excessive memory usage for large ClientHellos
		peekSize := recordLen + 5
		if peekSize > 2048 {
			peekSize = 2048
		}

		raw, err := br.Peek(peekSize)
		if err == nil || err == io.EOF {
			// Try to parse ClientHello specifically for JA3
			fp, err := FullFingerprintFromRaw(raw)
			if err == nil {
				// Store the fingerprint early
				l.Store.Store(conn.RemoteAddr().String(), &ConnectionFingerprint{
					RemoteAddr: conn.RemoteAddr().String(),
					JA3:        fp.JA3,
					JA4:        fp.JA4,
					Raw:        fp.ClientHello,
				})

				// EARLY REJECT LOGIC
				// If system is under attack and JA3 is a known malicious tool, drop NOW
				if l.IsUnderAttack != nil && l.IsUnderAttack() {
					db := GetDB()
					info, ok := db.LookupJA3(fp.JA3.Hash)

					// Rejection Threshold: Trust Score < 10 (Bot/Attack Tool)
					if ok && info.TrustScore < 10 {
						atomic.AddInt64(&globalEarlyRejectStats.TotalRejected, 1)
						logger.Warn("TLS Early Reject triggered",
							"ip", conn.RemoteAddr().String(),
							"ja3", fp.JA3.Hash,
							"tool", info.Name,
							"score", info.TrustScore,
						)
						conn.Close()
						return nil, fmt.Errorf("early reject: known attack tool")
					}
				}
			}
		}
	}

	return &BufferedConn{Conn: conn, Reader: br}, nil
}

// BufferedConn wraps a net.Conn with a buffered reader to replay peeked bytes
type BufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (c *BufferedConn) Read(b []byte) (n int, err error) {
	return c.Reader.Read(b)
}

func (c *BufferedConn) Close() error {
	return c.Conn.Close()
}
