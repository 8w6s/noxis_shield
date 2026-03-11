package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// ParseClientHello parses a raw TLS ClientHello message and extracts fingerprint parameters
func ParseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record")
	}

	// TLS Record Header: ContentType(1) + Version(2) + Length(2)
	contentType := data[0]
	if contentType != 0x16 { // Handshake
		return nil, fmt.Errorf("not a handshake record: 0x%02x", contentType)
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return nil, fmt.Errorf("incomplete record: need %d, have %d", 5+recordLen, len(data))
	}

	hs := data[5 : 5+recordLen]
	if len(hs) < 4 {
		return nil, fmt.Errorf("handshake too short")
	}

	// Handshake header: type(1) + length(3)
	hsType := hs[0]
	if hsType != 0x01 { // ClientHello
		return nil, fmt.Errorf("not ClientHello: 0x%02x", hsType)
	}

	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return nil, fmt.Errorf("incomplete ClientHello")
	}

	ch := hs[4 : 4+hsLen]
	return parseClientHelloBody(ch)
}

// ClientHelloInfo holds parsed TLS ClientHello data
type ClientHelloInfo struct {
	TLSVersion        uint16
	CipherSuites      []uint16
	Extensions        []uint16
	EllipticCurves    []uint16
	ECPointFormats    []uint8
	SignatureAlgs     []uint16
	ALPN              []string
	ServerName        string
	SupportedVersions []uint16
}

func parseClientHelloBody(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 34 {
		return nil, fmt.Errorf("ClientHello body too short")
	}

	info := &ClientHelloInfo{}

	// Client version (2 bytes)
	info.TLSVersion = binary.BigEndian.Uint16(data[0:2])

	// Random (32 bytes) — skip
	pos := 34

	// Session ID
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated at session ID")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher Suites
	if pos+2 > len(data) {
		return nil, fmt.Errorf("truncated at cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+csLen > len(data) {
		return nil, fmt.Errorf("truncated at cipher suites")
	}

	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[pos+i : pos+i+2])
		info.CipherSuites = append(info.CipherSuites, cs)
	}
	pos += csLen

	// Compression methods
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated at compression methods")
	}
	compLen := int(data[pos])
	pos += 1 + compLen

	// Extensions
	if pos+2 > len(data) {
		return info, nil // No extensions
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	extEnd := pos + extTotalLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		info.Extensions = append(info.Extensions, extType)

		extData := data[pos:]
		if len(extData) > extLen {
			extData = extData[:extLen]
		}

		switch extType {
		case 0x0000: // server_name
			info.ServerName = parseServerName(extData)
		case 0x000a: // supported_groups (elliptic_curves)
			info.EllipticCurves = parseSupportedGroups(extData)
		case 0x000b: // ec_point_formats
			info.ECPointFormats = parseECPointFormats(extData)
		case 0x000d: // signature_algorithms
			info.SignatureAlgs = parseSignatureAlgorithms(extData)
		case 0x0010: // ALPN
			info.ALPN = parseALPN(extData)
		case 0x002b: // supported_versions
			info.SupportedVersions = parseSupportedVersions(extData)
		}

		pos += extLen
	}

	// If supported_versions present, use the highest one as real TLS version
	if len(info.SupportedVersions) > 0 {
		maxVer := uint16(0)
		for _, v := range info.SupportedVersions {
			if v > maxVer && !isGREASE(v) {
				maxVer = v
			}
		}
		if maxVer > 0 {
			info.TLSVersion = maxVer
		}
	}

	return info, nil
}

func parseServerName(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// SNI list length (2) + type (1) + name length (2)
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+nameLen {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseSupportedGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	var groups []uint16
	for i := 2; i+1 < 2+listLen && i+1 < len(data); i += 2 {
		groups = append(groups, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return groups
}

func parseECPointFormats(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	fmtLen := int(data[0])
	var formats []uint8
	for i := 1; i < 1+fmtLen && i < len(data); i++ {
		formats = append(formats, data[i])
	}
	return formats
}

func parseSignatureAlgorithms(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	var algs []uint16
	for i := 2; i+1 < 2+listLen && i+1 < len(data); i += 2 {
		algs = append(algs, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return algs
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	var protos []string
	pos := 2
	for pos < 2+listLen && pos < len(data) {
		pLen := int(data[pos])
		pos++
		if pos+pLen > len(data) {
			break
		}
		protos = append(protos, string(data[pos:pos+pLen]))
		pos += pLen
	}
	return protos
}

func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	var versions []uint16
	for i := 1; i+1 < 1+listLen && i+1 < len(data); i += 2 {
		versions = append(versions, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return versions
}

// ComputeJA3FromClientHello computes JA3 hash from parsed ClientHello
func ComputeJA3FromClientHello(info *ClientHelloInfo) JA3Result {
	return JA3(
		info.TLSVersion,
		info.CipherSuites,
		info.Extensions,
		info.EllipticCurves,
		info.ECPointFormats,
	)
}

// ComputeJA4FromClientHello computes JA4 hash from parsed ClientHello
func ComputeJA4FromClientHello(info *ClientHelloInfo) JA4Result {
	alpn := ""
	if len(info.ALPN) > 0 {
		alpn = info.ALPN[0]
	}
	return JA4(
		"tcp",
		info.TLSVersion,
		info.ServerName,
		info.CipherSuites,
		info.Extensions,
		info.SignatureAlgs,
		alpn,
	)
}

// FullFingerprintFromRaw does a complete fingerprint from raw TLS ClientHello bytes
func FullFingerprintFromRaw(rawClientHello []byte) (*FullFingerprint, error) {
	info, err := ParseClientHello(rawClientHello)
	if err != nil {
		return nil, err
	}

	ja3 := ComputeJA3FromClientHello(info)
	ja4 := ComputeJA4FromClientHello(info)

	return &FullFingerprint{
		ClientHello: info,
		JA3:         ja3,
		JA4:         ja4,
		ServerName:  info.ServerName,
	}, nil
}

// FullFingerprint holds all fingerprint data for a connection
type FullFingerprint struct {
	ClientHello *ClientHelloInfo
	JA3         JA3Result
	JA4         JA4Result
	H2          H2Fingerprint
	ServerName  string
	Composite   CompositeScore
}

// isGREASE is duplicated here to avoid circular reference in this file context
func isGREASEVal(val uint16) bool {
	return (val & 0x0f0f) == 0x0a0a
}

// JA3RawString builds the raw JA3 string for debugging
func JA3RawString(info *ClientHelloInfo) string {
	cs := filterGREASE16(info.CipherSuites)
	ext := filterGREASE16(info.Extensions)
	ec := filterGREASE16(info.EllipticCurves)

	parts := make([]string, 5)
	parts[0] = strconv.Itoa(int(info.TLSVersion))
	parts[1] = joinUint16(cs, "-")
	parts[2] = joinUint16(ext, "-")
	parts[3] = joinUint16(ec, "-")

	ecpf := make([]string, len(info.ECPointFormats))
	for i, v := range info.ECPointFormats {
		ecpf[i] = strconv.Itoa(int(v))
	}
	parts[4] = strings.Join(ecpf, "-")

	raw := strings.Join(parts, ",")
	hash := fmt.Sprintf("%x", md5.Sum([]byte(raw)))

	return fmt.Sprintf("JA3: %s | Raw: %s", hash, raw)
}
