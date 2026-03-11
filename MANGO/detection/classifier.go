package detection

import (
	"strings"
	"sync"
	"time"

	"mango-waf/fingerprint"
)

// BotClassifier classifies traffic as human, bot, or specific bot type
type BotClassifier struct {
	signatures []BotSignature
	cache      sync.Map // map[string]*BotClassResult
}

// BotSignature defines a pattern for bot detection
type BotSignature struct {
	Name     string
	Category string // scraper, crawler, ddos_tool, scanner, automation
	Threat   string // low, medium, high, critical
	MatchFn  func(req *ClassifyRequest) bool
}

// ClassifyRequest holds all data needed for classification
type ClassifyRequest struct {
	IP          string
	UserAgent   string
	Headers     map[string]string
	URL         string
	Method      string
	Fingerprint *fingerprint.ConnectionFingerprint
	Behavior    *BehaviorVerdict
}

// BotClassResult is the bot classification result
type BotClassResult struct {
	IsBot      bool
	BotType    string  // "legitimate_bot", "malicious_bot", "automation", "ddos_tool", "scraper", "scanner"
	BotName    string  // Specific bot name if identified
	Confidence float64 // 0.0-1.0
	Threat     string  // "none", "low", "medium", "high", "critical"
	Reasons    []string
	CachedAt   time.Time
}

// NewBotClassifier creates a new bot classifier with built-in signatures
func NewBotClassifier() *BotClassifier {
	bc := &BotClassifier{}
	bc.loadDefaultSignatures()
	return bc
}

// Classify determines if a request is from a bot
func (bc *BotClassifier) Classify(req *ClassifyRequest) *BotClassResult {
	// Check cache (short TTL)
	if cached, ok := bc.cache.Load(req.IP); ok {
		result := cached.(*BotClassResult)
		if time.Since(result.CachedAt) < 30*time.Second {
			return result
		}
	}

	result := &BotClassResult{
		Threat:  "none",
		Reasons: make([]string, 0),
	}

	// Run all signatures
	matchCount := 0
	highestThreat := "none"

	for _, sig := range bc.signatures {
		if sig.MatchFn(req) {
			matchCount++
			result.Reasons = append(result.Reasons, sig.Name)

			if sig.Category != "" && result.BotType == "" {
				result.BotType = sig.Category
			}
			if sig.Name != "" && result.BotName == "" {
				result.BotName = sig.Name
			}
			if threatHigher(sig.Threat, highestThreat) {
				highestThreat = sig.Threat
			}
		}
	}

	// Combine with fingerprint data
	if req.Fingerprint != nil {
		if req.Fingerprint.Composite.Total < 30 {
			matchCount += 2
			result.Reasons = append(result.Reasons, "low_fp_trust")
		}
		if req.Fingerprint.JA3.Known && req.Fingerprint.JA3.TrustScore < 10 {
			matchCount += 3
			result.Reasons = append(result.Reasons, "known_tool_ja3")
			result.BotType = "ddos_tool"
		}
	}

	// Combine with behavioral analysis
	if req.Behavior != nil {
		if req.Behavior.IsBot {
			matchCount += 2
			result.Reasons = append(result.Reasons, "behavior_bot:"+req.Behavior.Profile)
		}
		if req.Behavior.Score < 30 {
			matchCount += 2
		}
	}

	// Final classification
	result.Confidence = float64(matchCount) / 10.0
	if result.Confidence > 1.0 {
		result.Confidence = 1.0
	}

	if matchCount >= 3 {
		result.IsBot = true
		result.Threat = highestThreat
	} else if matchCount >= 2 {
		result.IsBot = true
		result.Threat = "low"
	}

	result.CachedAt = time.Now()
	bc.cache.Store(req.IP, result)
	return result
}

// loadDefaultSignatures loads built-in bot detection signatures
func (bc *BotClassifier) loadDefaultSignatures() {
	bc.signatures = []BotSignature{
		// --- Empty/Missing headers ---
		{
			Name:     "no_accept_header",
			Category: "automation",
			Threat:   "medium",
			MatchFn: func(req *ClassifyRequest) bool {
				_, ok := req.Headers["Accept"]
				return !ok || req.Headers["Accept"] == ""
			},
		},
		{
			Name:     "no_accept_language",
			Category: "automation",
			Threat:   "low",
			MatchFn: func(req *ClassifyRequest) bool {
				_, ok := req.Headers["Accept-Language"]
				return !ok
			},
		},
		{
			Name:     "no_accept_encoding",
			Category: "automation",
			Threat:   "low",
			MatchFn: func(req *ClassifyRequest) bool {
				_, ok := req.Headers["Accept-Encoding"]
				return !ok
			},
		},

		// --- Suspicious headers ---
		{
			Name:     "connection_close",
			Category: "ddos_tool",
			Threat:   "medium",
			MatchFn: func(req *ClassifyRequest) bool {
				return strings.ToLower(req.Headers["Connection"]) == "close"
			},
		},
		{
			Name:     "missing_referer_on_subresource",
			Category: "scraper",
			Threat:   "low",
			MatchFn: func(req *ClassifyRequest) bool {
				return isStaticResource(req.URL) && req.Headers["Referer"] == ""
			},
		},

		// --- Known DDoS tool user agents ---
		{
			Name:     "ddos_ua_mhddos",
			Category: "ddos_tool",
			Threat:   "critical",
			MatchFn: func(req *ClassifyRequest) bool {
				ua := strings.ToLower(req.UserAgent)
				ddosTools := []string{
					"mhddos", "loic", "hoic", "slowloris", "goldeneye",
					"hulk", "xerxes", "torshammer", "slowhttptest",
					"pyloris", "rudy", "thc-ssl", "apache-bench",
				}
				for _, tool := range ddosTools {
					if strings.Contains(ua, tool) {
						return true
					}
				}
				return false
			},
		},

		// --- Header order anomalies ---
		{
			Name:     "ua_browser_no_sec_headers",
			Category: "automation",
			Threat:   "medium",
			MatchFn: func(req *ClassifyRequest) bool {
				ua := strings.ToLower(req.UserAgent)
				isBrowserUA := strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox")
				_, hasSFP := req.Headers["Sec-Fetch-Mode"]
				_, hasSFD := req.Headers["Sec-Fetch-Dest"]
				return isBrowserUA && !hasSFP && !hasSFD
			},
		},

		// --- Content analysis ---
		{
			Name:     "post_no_content_type",
			Category: "scanner",
			Threat:   "medium",
			MatchFn: func(req *ClassifyRequest) bool {
				return req.Method == "POST" && req.Headers["Content-Type"] == ""
			},
		},

		// --- Suspicious URL patterns ---
		{
			Name:     "path_traversal_attempt",
			Category: "scanner",
			Threat:   "high",
			MatchFn: func(req *ClassifyRequest) bool {
				return strings.Contains(req.URL, "..") ||
					strings.Contains(req.URL, ".env") ||
					strings.Contains(req.URL, "wp-login") ||
					strings.Contains(req.URL, "phpmyadmin") ||
					strings.Contains(req.URL, ".git/")
			},
		},
		{
			Name:     "sql_injection_probe",
			Category: "scanner",
			Threat:   "high",
			MatchFn: func(req *ClassifyRequest) bool {
				url := strings.ToLower(req.URL)
				return strings.Contains(url, "union+select") ||
					strings.Contains(url, "' or '1'='1") ||
					strings.Contains(url, "1=1") ||
					strings.Contains(url, "sleep(") ||
					strings.Contains(url, "benchmark(")
			},
		},

		// --- Legitimate bot detection (positive signal) ---
		{
			Name:     "googlebot",
			Category: "legitimate_bot",
			Threat:   "none",
			MatchFn: func(req *ClassifyRequest) bool {
				ua := strings.ToLower(req.UserAgent)
				return strings.Contains(ua, "googlebot") || strings.Contains(ua, "google-inspectiontool")
			},
		},
		{
			Name:     "bingbot",
			Category: "legitimate_bot",
			Threat:   "none",
			MatchFn: func(req *ClassifyRequest) bool {
				return strings.Contains(strings.ToLower(req.UserAgent), "bingbot")
			},
		},
	}
}

// CleanupCache clears stale cache entries
func (bc *BotClassifier) CleanupCache() {
	bc.cache.Range(func(key, value interface{}) bool {
		result := value.(*BotClassResult)
		if time.Since(result.CachedAt) > 5*time.Minute {
			bc.cache.Delete(key)
		}
		return true
	})
}

func threatHigher(a, b string) bool {
	levels := map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	return levels[a] > levels[b]
}
