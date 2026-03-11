package fingerprint

import (
	"crypto/tls"
	"net"
	"sync"

	"mango-waf/logger"
)

// TLSInterceptor wraps a TLS listener to capture ClientHello for fingerprinting
type TLSInterceptor struct {
	inner     net.Listener
	store     *FingerprintStore
	tlsConfig *tls.Config
}

// FingerprintStore stores fingerprints per-connection
type FingerprintStore struct {
	mu    sync.RWMutex
	cache map[string]*ConnectionFingerprint // key: remote addr
}

// ConnectionFingerprint holds all fingerprints for a single connection
type ConnectionFingerprint struct {
	RemoteAddr string
	JA3        JA3Result
	JA4        JA4Result
	H2         H2Fingerprint
	Composite  CompositeScore
	UserAgent  string
	Raw        *ClientHelloInfo
}

// NewFingerprintStore creates a new fingerprint store
func NewFingerprintStore() *FingerprintStore {
	return &FingerprintStore{
		cache: make(map[string]*ConnectionFingerprint),
	}
}

// Store stores a fingerprint for a remote address
func (fs *FingerprintStore) Store(addr string, fp *ConnectionFingerprint) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.cache[addr] = fp
}

// Lookup retrieves a fingerprint for a remote address
func (fs *FingerprintStore) Lookup(addr string) (*ConnectionFingerprint, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	fp, ok := fs.cache[addr]
	return fp, ok
}

// Remove removes a fingerprint entry
func (fs *FingerprintStore) Remove(addr string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.cache, addr)
}

// Cleanup removes old entries (call periodically)
func (fs *FingerprintStore) Cleanup(maxEntries int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.cache) > maxEntries {
		// Simple eviction: clear half
		count := 0
		for k := range fs.cache {
			delete(fs.cache, k)
			count++
			if count >= len(fs.cache)/2 {
				break
			}
		}
	}
}

// Size returns the number of stored fingerprints
func (fs *FingerprintStore) Size() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.cache)
}

// NewTLSInterceptor creates a TLS listener that captures ClientHello
func NewTLSInterceptor(inner net.Listener, tlsConfig *tls.Config, store *FingerprintStore) *TLSInterceptor {
	// Configure GetConfigForClient to intercept ClientHello
	originalGetConfig := tlsConfig.GetConfigForClient

	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Extract fingerprint from the ClientHello
		fp := extractFromStdlibHello(hello)
		if fp != nil {
			store.Store(hello.Conn.RemoteAddr().String(), fp)
			logger.Debug("TLS fingerprint captured",
				"remote", hello.Conn.RemoteAddr().String(),
				"ja3", fp.JA3.Hash,
				"sni", hello.ServerName,
				"known", fp.JA3.Known,
			)
		}

		if originalGetConfig != nil {
			return originalGetConfig(hello)
		}
		return nil, nil
	}

	return &TLSInterceptor{
		inner:     inner,
		store:     store,
		tlsConfig: tlsConfig,
	}
}

// extractFromStdlibHello extracts fingerprint data from Go's tls.ClientHelloInfo
func extractFromStdlibHello(hello *tls.ClientHelloInfo) *ConnectionFingerprint {
	fp := &ConnectionFingerprint{
		RemoteAddr: hello.Conn.RemoteAddr().String(),
	}

	// Convert Go's ClientHelloInfo to our format
	info := &ClientHelloInfo{
		ServerName: hello.ServerName,
	}

	// CipherSuites
	info.CipherSuites = hello.CipherSuites

	// SupportedVersions
	info.SupportedVersions = hello.SupportedVersions

	// Determine TLS version from SupportedVersions
	if len(hello.SupportedVersions) > 0 {
		maxVer := uint16(0)
		for _, v := range hello.SupportedVersions {
			if v > maxVer && !isGREASE(v) {
				maxVer = v
			}
		}
		info.TLSVersion = maxVer
	}

	// SupportedCurves → EllipticCurves
	for _, curve := range hello.SupportedCurves {
		info.EllipticCurves = append(info.EllipticCurves, uint16(curve))
	}

	// SupportedPoints → ECPointFormats
	info.ECPointFormats = hello.SupportedPoints

	// ALPN
	info.ALPN = hello.SupportedProtos

	// SignatureSchemes → SignatureAlgs
	for _, scheme := range hello.SignatureSchemes {
		info.SignatureAlgs = append(info.SignatureAlgs, uint16(scheme))
	}

	// Compute JA3
	fp.JA3 = ComputeJA3FromClientHello(info)

	// Compute JA4
	fp.JA4 = ComputeJA4FromClientHello(info)

	fp.Raw = info
	return fp
}

// GetCompositeForRequest computes composite score for a request
func (fs *FingerprintStore) GetCompositeForRequest(remoteAddr, userAgent string) *ConnectionFingerprint {
	fp, ok := fs.Lookup(remoteAddr)
	if !ok {
		return nil
	}

	// Update UA and compute composite
	fp.UserAgent = userAgent
	fp.Composite = CalculateComposite(fp.JA3, fp.JA4, fp.H2, userAgent)

	return fp
}

// IsSuspicious returns true if the fingerprint indicates a bot/tool
func (fp *ConnectionFingerprint) IsSuspicious() bool {
	return fp.Composite.Total < 40
}

// IsTrusted returns true if the fingerprint indicates a legitimate browser
func (fp *ConnectionFingerprint) IsTrusted() bool {
	return fp.Composite.Total >= 75
}

// GetTrustLevel returns a human-readable trust level
func (fp *ConnectionFingerprint) GetTrustLevel() string {
	return fp.Composite.Verdict
}
