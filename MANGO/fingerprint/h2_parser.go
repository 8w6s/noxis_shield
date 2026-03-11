package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
)

// H2FrameType represents HTTP/2 frame types
type H2FrameType uint8

const (
	H2FrameData         H2FrameType = 0x00
	H2FrameHeaders      H2FrameType = 0x01
	H2FramePriority     H2FrameType = 0x02
	H2FrameRSTStream    H2FrameType = 0x03
	H2FrameSettings     H2FrameType = 0x04
	H2FramePushPromise  H2FrameType = 0x05
	H2FramePing         H2FrameType = 0x06
	H2FrameGoaway       H2FrameType = 0x07
	H2FrameWindowUpdate H2FrameType = 0x08
	H2FrameContinuation H2FrameType = 0x09
)

// H2SettingID represents HTTP/2 settings parameter IDs
type H2SettingID uint16

const (
	H2SettingHeaderTableSize      H2SettingID = 0x01
	H2SettingEnablePush           H2SettingID = 0x02
	H2SettingMaxConcurrentStreams H2SettingID = 0x03
	H2SettingInitialWindowSize    H2SettingID = 0x04
	H2SettingMaxFrameSize         H2SettingID = 0x05
	H2SettingMaxHeaderListSize    H2SettingID = 0x06
)

// H2Frame represents a parsed HTTP/2 frame
type H2Frame struct {
	Length   uint32
	Type     H2FrameType
	Flags    uint8
	StreamID uint32
	Payload  []byte
}

// H2SettingPair holds a settings key-value
type H2SettingPair struct {
	ID    H2SettingID
	Value uint32
}

// H2PriorityInfo holds PRIORITY frame data
type H2PriorityInfo struct {
	StreamID  uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint8
}

// ParseH2Preface checks for HTTP/2 connection preface
func ParseH2Preface(data []byte) bool {
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	return len(data) >= len(preface) && string(data[:len(preface)]) == preface
}

// ParseH2Frames parses HTTP/2 frames from raw data (after the preface)
func ParseH2Frames(data []byte) ([]H2Frame, error) {
	var frames []H2Frame
	pos := 0

	// Skip HTTP/2 preface if present
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if len(data) >= len(preface) && string(data[:len(preface)]) == preface {
		pos = len(preface)
	}

	for pos+9 <= len(data) {
		// Frame header: Length(3) + Type(1) + Flags(1) + StreamID(4)
		length := uint32(data[pos])<<16 | uint32(data[pos+1])<<8 | uint32(data[pos+2])
		frameType := H2FrameType(data[pos+3])
		flags := data[pos+4]
		streamID := binary.BigEndian.Uint32(data[pos+5:pos+9]) & 0x7FFFFFFF
		pos += 9

		if pos+int(length) > len(data) {
			break // Incomplete frame
		}

		payload := make([]byte, length)
		copy(payload, data[pos:pos+int(length)])
		pos += int(length)

		frames = append(frames, H2Frame{
			Length:   length,
			Type:     frameType,
			Flags:    flags,
			StreamID: streamID,
			Payload:  payload,
		})

		// Limit to first 20 frames
		if len(frames) >= 20 {
			break
		}
	}

	return frames, nil
}

// ParseH2SettingsFrame parses SETTINGS frame payload
func ParseH2SettingsFrame(payload []byte) []H2SettingPair {
	var settings []H2SettingPair
	for i := 0; i+5 < len(payload); i += 6 {
		id := H2SettingID(binary.BigEndian.Uint16(payload[i : i+2]))
		value := binary.BigEndian.Uint32(payload[i+2 : i+6])
		settings = append(settings, H2SettingPair{ID: id, Value: value})
	}
	return settings
}

// ParseH2PriorityFrame parses PRIORITY frame payload
func ParseH2PriorityFrame(payload []byte, streamID uint32) *H2PriorityInfo {
	if len(payload) < 5 {
		return nil
	}
	depAndExcl := binary.BigEndian.Uint32(payload[0:4])
	return &H2PriorityInfo{
		StreamID:  streamID,
		Exclusive: depAndExcl&0x80000000 != 0,
		DependsOn: depAndExcl & 0x7FFFFFFF,
		Weight:    payload[4],
	}
}

// ExtractH2Fingerprint extracts a full HTTP/2 fingerprint from parsed frames
func ExtractH2Fingerprint(frames []H2Frame) H2Fingerprint {
	fp := H2Fingerprint{}

	var settingsOrder []string
	var priorities []string
	windowUpdate := uint32(0)

	settings := H2Settings{}

	for _, frame := range frames {
		switch frame.Type {
		case H2FrameSettings:
			if frame.Flags&0x01 != 0 {
				continue // ACK, skip
			}
			pairs := ParseH2SettingsFrame(frame.Payload)
			for _, p := range pairs {
				settingsOrder = append(settingsOrder, fmt.Sprintf("%d:%d", p.ID, p.Value))
				settings.SettingsOrder = append(settings.SettingsOrder, uint16(p.ID))
				switch p.ID {
				case H2SettingHeaderTableSize:
					settings.HeaderTableSize = p.Value
				case H2SettingEnablePush:
					settings.EnablePush = p.Value
				case H2SettingMaxConcurrentStreams:
					settings.MaxConcurrentStreams = p.Value
				case H2SettingInitialWindowSize:
					settings.InitialWindowSize = p.Value
				case H2SettingMaxFrameSize:
					settings.MaxFrameSize = p.Value
				case H2SettingMaxHeaderListSize:
					settings.MaxHeaderListSize = p.Value
				}
			}

		case H2FrameWindowUpdate:
			if len(frame.Payload) >= 4 {
				windowUpdate = binary.BigEndian.Uint32(frame.Payload[0:4]) & 0x7FFFFFFF
			}

		case H2FramePriority:
			pri := ParseH2PriorityFrame(frame.Payload, frame.StreamID)
			if pri != nil {
				excl := 0
				if pri.Exclusive {
					excl = 1
				}
				priorities = append(priorities, fmt.Sprintf("%d:%d:%d:%d",
					pri.StreamID, excl, pri.DependsOn, pri.Weight))
			}

		case H2FrameHeaders:
			// Extract pseudo-header order from HEADERS frame
			// (In production, would need HPACK decoder)
			if frame.Flags&0x20 != 0 { // PRIORITY flag
				if len(frame.Payload) >= 5 {
					pri := ParseH2PriorityFrame(frame.Payload[:5], frame.StreamID)
					if pri != nil {
						excl := 0
						if pri.Exclusive {
							excl = 1
						}
						priorities = append(priorities, fmt.Sprintf("%d:%d:%d:%d",
							pri.StreamID, excl, pri.DependsOn, pri.Weight))
					}
				}
			}
		}
	}

	fp.SettingsOrder = strings.Join(settingsOrder, ";")
	fp.WindowUpdate = windowUpdate
	fp.PriorityFrames = strings.Join(priorities, "|")

	// Compute the hash
	raw := fp.SettingsOrder + "|" + fmt.Sprintf("%d", windowUpdate) + "|" + fp.PriorityFrames
	fp.Hash = fmt.Sprintf("%x", md5Hash([]byte(raw)))

	// Check known H2 fingerprints
	if info, ok := knownH2DB.Load(fp.Hash); ok {
		bi := info.(*BrowserInfo)
		fp.Known = true
		fp.TrustScore = bi.TrustScore
	}

	return fp
}

func md5Hash(data []byte) [16]byte {
	return md5.Sum(data)
}

// H2FingerprintString returns a human-readable H2 fingerprint string
func H2FingerprintString(fp H2Fingerprint) string {
	return fmt.Sprintf("H2FP: %s | Settings: %s | WU: %d | Priority: %s",
		fp.Hash, fp.SettingsOrder, fp.WindowUpdate, fp.PriorityFrames)
}

// ==================================================================
// Known HTTP/2 Fingerprint Database
// ==================================================================

// InitKnownH2Fingerprints loads known HTTP/2 fingerprints into the database
func InitKnownH2Fingerprints() {
	// Chrome typical H2 fingerprint
	// SETTINGS order: HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE
	// Chrome: 1:65536;3:1000;4:6291456;2:0 | WU: 15663105
	chromeH2 := []struct {
		hash  string
		name  string
		score float64
	}{
		{"chrome_h2_120", "Chrome 120+", 90},
		{"chrome_h2_110", "Chrome 110-119", 88},
		{"chrome_h2_android", "Chrome Android", 85},
	}
	for _, c := range chromeH2 {
		knownH2DB.Store(c.hash, &BrowserInfo{
			Name: c.name, TrustScore: c.score,
		})
	}

	// Firefox typical H2 fingerprint
	// Firefox: 1:65536;4:131072;5:16384 | WU: 12517377
	firefoxH2 := []struct {
		hash  string
		name  string
		score float64
	}{
		{"firefox_h2_120", "Firefox 120+", 90},
		{"firefox_h2_esr", "Firefox ESR", 85},
	}
	for _, f := range firefoxH2 {
		knownH2DB.Store(f.hash, &BrowserInfo{
			Name: f.name, TrustScore: f.score,
		})
	}

	// Safari typical H2 fingerprint
	// Safari: 4:4194304;3:100 | WU: 10485760
	knownH2DB.Store("safari_h2_17", &BrowserInfo{
		Name: "Safari 17+", TrustScore: 90,
	})

	// Known bot/tool H2 fingerprints (low trust)
	botH2 := []string{
		"golang_h2_default",
		"python_h2_default",
		"node_h2_default",
		"curl_h2_default",
	}
	for _, h := range botH2 {
		knownH2DB.Store(h, &BrowserInfo{
			Name: "Bot/Tool", TrustScore: 5,
		})
	}
}
