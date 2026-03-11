package fingerprint

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// JA3Result holds the JA3 fingerprint result
type JA3Result struct {
	Hash       string
	Raw        string
	TLSVersion uint16
	Known      bool
	BrowserID  string
	TrustScore float64
}

// JA3 computes JA3 fingerprint from TLS ClientHello parameters
func JA3(version uint16, cipherSuites []uint16, extensions []uint16,
	ellipticCurves []uint16, ecPointFormats []uint8) JA3Result {

	// Build JA3 raw string: version,ciphersuites,extensions,elliptic_curves,ec_point_formats
	parts := make([]string, 5)

	// TLS version
	parts[0] = strconv.Itoa(int(version))

	// Cipher suites (exclude GREASE values)
	cs := filterGREASE16(cipherSuites)
	parts[1] = joinUint16(cs, "-")

	// Extensions (exclude GREASE values)
	ext := filterGREASE16(extensions)
	parts[2] = joinUint16(ext, "-")

	// Elliptic curves (exclude GREASE values)
	ec := filterGREASE16(ellipticCurves)
	parts[3] = joinUint16(ec, "-")

	// EC point formats
	ecpf := make([]string, len(ecPointFormats))
	for i, v := range ecPointFormats {
		ecpf[i] = strconv.Itoa(int(v))
	}
	parts[4] = strings.Join(ecpf, "-")

	raw := strings.Join(parts, ",")
	hash := fmt.Sprintf("%x", md5.Sum([]byte(raw)))

	result := JA3Result{
		Hash:       hash,
		Raw:        raw,
		TLSVersion: version,
	}

	// Check against known browser database
	if info, ok := knownJA3DB.Load(hash); ok {
		bi := info.(*BrowserInfo)
		result.Known = true
		result.BrowserID = bi.Name
		result.TrustScore = bi.TrustScore
	}

	return result
}

// filterGREASE16 removes GREASE values from uint16 slice
func filterGREASE16(values []uint16) []uint16 {
	result := make([]uint16, 0, len(values))
	for _, v := range values {
		if !isGREASE(v) {
			result = append(result, v)
		}
	}
	return result
}

// isGREASE checks if a value is a GREASE (Generate Random Extensions And Sustain Extensibility) value
func isGREASE(val uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
	return (val & 0x0f0f) == 0x0a0a
}

func joinUint16(values []uint16, sep string) string {
	strs := make([]string, len(values))
	for i, v := range values {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, sep)
}

// ================================================
// JA4 Fingerprinting (advanced)
// ================================================

// JA4Result holds JA4 fingerprint result
type JA4Result struct {
	Hash       string
	Raw        string
	TLSVersion string
	SNI        string
	Known      bool
	TrustScore float64
}

// JA4 computes JA4 fingerprint (more advanced than JA3)
func JA4(proto string, version uint16, sni string, cipherSuites []uint16,
	extensions []uint16, sigAlgs []uint16, alpn string) JA4Result {

	// JA4 format: proto_version_sni_ciphercount_extcount_alpn_cipherhash_exthash
	var parts []string

	// Protocol type
	switch proto {
	case "tcp":
		parts = append(parts, "t")
	case "quic":
		parts = append(parts, "q")
	default:
		parts = append(parts, "t")
	}

	// TLS version
	var ver string
	switch version {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	default:
		ver = "00"
	}
	parts = append(parts, ver)

	// SNI indicator
	if sni != "" {
		parts = append(parts, "d")
	} else {
		parts = append(parts, "i")
	}

	// Cipher suite count
	cs := filterGREASE16(cipherSuites)
	parts = append(parts, fmt.Sprintf("%02d", len(cs)))

	// Extension count
	ext := filterGREASE16(extensions)
	parts = append(parts, fmt.Sprintf("%02d", len(ext)))

	// ALPN first value
	if alpn != "" {
		parts = append(parts, alpn[:2])
	} else {
		parts = append(parts, "00")
	}

	// Cipher suites hash (sorted, SHA256 truncated)
	sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
	csHash := truncatedHash(joinUint16(cs, ","), 12)
	parts = append(parts, csHash)

	// Extensions hash (sorted, SHA256 truncated)
	sort.Slice(ext, func(i, j int) bool { return ext[i] < ext[j] })
	extHash := truncatedHash(joinUint16(ext, ","), 12)
	parts = append(parts, extHash)

	raw := strings.Join(parts[:6], "")
	hash := raw + "_" + csHash + "_" + extHash

	result := JA4Result{
		Hash:       hash,
		Raw:        strings.Join(parts, "_"),
		TLSVersion: ver,
		SNI:        sni,
	}

	return result
}

func truncatedHash(input string, length int) string {
	h := fmt.Sprintf("%x", md5.Sum([]byte(input)))
	if len(h) > length {
		return h[:length]
	}
	return h
}

// ================================================
// HTTP/2 Fingerprinting
// ================================================

// H2Fingerprint holds HTTP/2 fingerprint data
type H2Fingerprint struct {
	Hash           string
	SettingsOrder  string
	WindowUpdate   uint32
	PriorityFrames string
	HeaderOrder    string
	Known          bool
	TrustScore     float64
}

// H2Settings represents HTTP/2 SETTINGS frame parameters
type H2Settings struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
	SettingsOrder        []uint16 // Order of settings IDs
}

// ComputeH2Fingerprint computes HTTP/2 fingerprint from SETTINGS frame
func ComputeH2Fingerprint(settings H2Settings, windowUpdate uint32) H2Fingerprint {
	// Build fingerprint from settings order and values
	var parts []string

	for _, id := range settings.SettingsOrder {
		var val uint32
		switch id {
		case 1:
			val = settings.HeaderTableSize
		case 2:
			val = settings.EnablePush
		case 3:
			val = settings.MaxConcurrentStreams
		case 4:
			val = settings.InitialWindowSize
		case 5:
			val = settings.MaxFrameSize
		case 6:
			val = settings.MaxHeaderListSize
		}
		parts = append(parts, fmt.Sprintf("%d:%d", id, val))
	}

	raw := strings.Join(parts, ";") + "|" + strconv.Itoa(int(windowUpdate))
	hash := fmt.Sprintf("%x", md5.Sum([]byte(raw)))

	fp := H2Fingerprint{
		Hash:          hash,
		SettingsOrder: strings.Join(parts, ";"),
		WindowUpdate:  windowUpdate,
	}

	// Check known database
	if info, ok := knownH2DB.Load(hash); ok {
		bi := info.(*BrowserInfo)
		fp.Known = true
		fp.TrustScore = bi.TrustScore
	}

	return fp
}

// ================================================
// Browser Database
// ================================================

// BrowserInfo stores info about a known browser fingerprint
type BrowserInfo struct {
	Name       string
	Version    string
	Platform   string
	TrustScore float64 // 0.0 - 100.0
}

var (
	knownJA3DB sync.Map
	knownH2DB  sync.Map
)

// InitKnownBrowsers initializes the known browser fingerprint database
func InitKnownBrowsers() {
	// Chrome fingerprints
	chromeFP := []string{
		"b32309a26951912be7dba376398abc3b", // Chrome 120+
		"cd08e31494f9531f560d64c695473da9", // Chrome 110-119
		"a0e9f5d64349fb13191bc781f81f42e1", // Chrome 100-109
		"b985f96c93d7ef2746a570e563b1e984", // Chrome Android
	}
	for _, h := range chromeFP {
		knownJA3DB.Store(h, &BrowserInfo{
			Name: "Chrome", TrustScore: 90,
		})
	}

	// Firefox fingerprints
	firefoxFP := []string{
		"588c4c43324290f3f1732d5975f6c3d6", // Firefox 120+
		"b4069ce0b3e88a1d82900c0e3a683e39", // Firefox 110-119
		"7d5faccf34ed5bea254b0e7fd4a60e20", // Firefox ESR
	}
	for _, h := range firefoxFP {
		knownJA3DB.Store(h, &BrowserInfo{
			Name: "Firefox", TrustScore: 90,
		})
	}

	// Safari fingerprints
	safariFP := []string{
		"773906b0efdefa24a7f2b8eb6985bf37", // Safari 17+
		"96a29f13c8b4c6573e7e2dfe5e14f9e0", // Safari iOS
	}
	for _, h := range safariFP {
		knownJA3DB.Store(h, &BrowserInfo{
			Name: "Safari", TrustScore: 90,
		})
	}

	// Edge fingerprints (based on Chromium)
	edgeFP := []string{
		"d5e710fb25a94a7f61f6d8a8a8c47a2d", // Edge 120+
	}
	for _, h := range edgeFP {
		knownJA3DB.Store(h, &BrowserInfo{
			Name: "Edge", TrustScore: 85,
		})
	}

	// Known bot/tool fingerprints (LOW trust)
	botFP := []string{
		"e7d705a3286e19ea42f587b344ee6865", // Python requests
		"36f1b0d87b0951c68ef6d7a0d5e0c6f0", // Go HTTP client
		"1138de370e523f55c8b4a065c4c2a8a6", // Node.js
		"6734f37431670b3ab4292b8f60f29984", // curl
		"209e1233aa450f8ac6a9d4a66f11e87f", // wget
	}
	for _, h := range botFP {
		knownJA3DB.Store(h, &BrowserInfo{
			Name: "Bot/Tool", TrustScore: 5,
		})
	}
}

// ================================================
// Composite Trust Score
// ================================================

// CompositeScore calculates a composite trust score from all fingerprints
type CompositeScore struct {
	JA3Score float64
	JA4Score float64
	H2Score  float64
	UAScore  float64
	Total    float64
	Verdict  string
}

// CalculateComposite computes composite trust score
func CalculateComposite(ja3 JA3Result, ja4 JA4Result, h2 H2Fingerprint, ua string) CompositeScore {
	score := CompositeScore{}

	// JA3 weight: 30%
	if ja3.Known {
		score.JA3Score = ja3.TrustScore
	} else {
		score.JA3Score = 20 // Unknown = suspicious
	}

	// JA4 weight: 25%
	if ja4.Known {
		score.JA4Score = ja4.TrustScore
	} else {
		score.JA4Score = 25
	}

	// H2 weight: 20%
	if h2.Known {
		score.H2Score = h2.TrustScore
	} else {
		score.H2Score = 30
	}

	// UA consistency weight: 25%
	score.UAScore = checkUAConsistency(ja3, ua)

	// Weighted total
	score.Total = score.JA3Score*0.30 + score.JA4Score*0.25 +
		score.H2Score*0.20 + score.UAScore*0.25

	// Verdict
	switch {
	case score.Total >= 80:
		score.Verdict = "trusted"
	case score.Total >= 60:
		score.Verdict = "normal"
	case score.Total >= 40:
		score.Verdict = "suspicious"
	case score.Total >= 20:
		score.Verdict = "likely_bot"
	default:
		score.Verdict = "malicious"
	}

	return score
}

// checkUAConsistency verifies User-Agent matches TLS fingerprint
func checkUAConsistency(ja3 JA3Result, ua string) float64 {
	ua = strings.ToLower(ua)

	if !ja3.Known {
		return 30
	}

	browserName := strings.ToLower(ja3.BrowserID)

	// Check if UA claims to be the same browser as the TLS fingerprint
	switch {
	case strings.Contains(browserName, "chrome") && strings.Contains(ua, "chrome"):
		return 95
	case strings.Contains(browserName, "firefox") && strings.Contains(ua, "firefox"):
		return 95
	case strings.Contains(browserName, "safari") && strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		return 95
	case strings.Contains(browserName, "edge") && strings.Contains(ua, "edg"):
		return 90
	case strings.Contains(browserName, "bot"):
		return 5
	default:
		// UA doesn't match TLS fingerprint = suspicious
		return 20
	}
}
