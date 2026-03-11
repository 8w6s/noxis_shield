package detection

import (
	"math"
	"strings"
	"sync"
	"time"
)

// BehaviorAnalyzer performs behavioral analysis on request patterns
type BehaviorAnalyzer struct {
	profiles sync.Map // map[string]*BehaviorProfile
}

// BehaviorProfile tracks behavioral patterns for one IP/session
type BehaviorProfile struct {
	mu          sync.Mutex
	IP          string
	FirstSeen   time.Time
	LastSeen    time.Time
	TotalReqs   int64
	WindowReqs  int64
	WindowStart time.Time

	// Request pattern analysis
	URLs         map[string]int
	Methods      map[string]int
	StatusCodes  map[int]int
	ContentTypes map[string]int
	UserAgents   map[string]int

	// Timing analysis
	IntervalSamples []float64 // ms between requests
	LastReqTime     time.Time

	// Path traversal patterns
	Depth4xx     int // deep path 4xx responses
	APIEndpoints int
	StaticReqs   int
	DynamicReqs  int

	// Computed scores
	EntropyScore    float64 // URL distribution entropy
	RegularityScore float64 // timing regularity (0 = random human, 1 = robot)
	DiversityScore  float64 // request diversity
	BotProbability  float64 // final bot probability 0.0-1.0
}

// BehaviorVerdict is the result of behavioral analysis
type BehaviorVerdict struct {
	Score        float64 // 0 = definitely bot, 100 = definitely human
	IsBot        bool
	IsSuspicious bool
	Reasons      []string
	Profile      string // "human", "bot", "scraper", "scanner", "ddos"
}

// NewBehaviorAnalyzer creates a new behavior analyzer
func NewBehaviorAnalyzer() *BehaviorAnalyzer {
	return &BehaviorAnalyzer{}
}

// Analyze processes a request and updates the behavioral profile
func (ba *BehaviorAnalyzer) Analyze(ip, url, method, ua string, statusCode int) *BehaviorVerdict {
	v, _ := ba.profiles.LoadOrStore(ip, &BehaviorProfile{
		IP:           ip,
		FirstSeen:    time.Now(),
		URLs:         make(map[string]int),
		Methods:      make(map[string]int),
		StatusCodes:  make(map[int]int),
		ContentTypes: make(map[string]int),
		UserAgents:   make(map[string]int),
	})

	profile := v.(*BehaviorProfile)
	profile.mu.Lock()
	defer profile.mu.Unlock()

	now := time.Now()
	profile.LastSeen = now
	profile.TotalReqs++

	// Track request interval
	if !profile.LastReqTime.IsZero() {
		interval := now.Sub(profile.LastReqTime).Seconds() * 1000 // ms
		if len(profile.IntervalSamples) < 1000 {
			profile.IntervalSamples = append(profile.IntervalSamples, interval)
		} else {
			// Sliding window
			profile.IntervalSamples = append(profile.IntervalSamples[1:], interval)
		}
	}
	profile.LastReqTime = now

	// Track patterns
	profile.URLs[normalizeURL(url)]++
	profile.Methods[method]++
	profile.StatusCodes[statusCode]++
	profile.UserAgents[ua]++

	// Classify request type
	if isStaticResource(url) {
		profile.StaticReqs++
	} else if isAPIEndpoint(url) {
		profile.APIEndpoints++
		profile.DynamicReqs++
	} else {
		profile.DynamicReqs++
	}

	if statusCode >= 400 && statusCode < 500 {
		profile.Depth4xx++
	}

	// Sliding window (5 minutes)
	if now.Sub(profile.WindowStart) > 5*time.Minute {
		profile.WindowReqs = 1
		profile.WindowStart = now
	} else {
		profile.WindowReqs++
	}

	// Compute verdict (only after enough samples)
	if profile.TotalReqs < 5 {
		return &BehaviorVerdict{Score: 70, Profile: "unknown"}
	}

	return profile.computeVerdict()
}

// computeVerdict calculates the behavioral verdict
func (p *BehaviorProfile) computeVerdict() *BehaviorVerdict {
	verdict := &BehaviorVerdict{
		Score:   100,
		Reasons: make([]string, 0),
	}

	// 1. Timing regularity analysis (weight: 25%)
	regularityPenalty := p.analyzeTimingRegularity()
	verdict.Score -= regularityPenalty * 0.25

	// 2. URL distribution entropy (weight: 20%)
	entropyPenalty := p.analyzeURLEntropy()
	verdict.Score -= entropyPenalty * 0.20

	// 3. Request diversity (weight: 20%)
	diversityPenalty := p.analyzeDiversity()
	verdict.Score -= diversityPenalty * 0.20

	// 4. Speed analysis (weight: 15%)
	speedPenalty := p.analyzeSpeed()
	verdict.Score -= speedPenalty * 0.15

	// 5. Error pattern (weight: 10%)
	errorPenalty := p.analyzeErrorPattern()
	verdict.Score -= errorPenalty * 0.10

	// 6. UA consistency (weight: 10%)
	uaPenalty := p.analyzeUAConsistency()
	verdict.Score -= uaPenalty * 0.10

	// Clamp
	if verdict.Score < 0 {
		verdict.Score = 0
	}

	// Classify
	switch {
	case verdict.Score < 20:
		verdict.IsBot = true
		verdict.Profile = "ddos"
		verdict.Reasons = append(verdict.Reasons, "extreme_bot_behavior")
	case verdict.Score < 40:
		verdict.IsBot = true
		verdict.Profile = "bot"
		verdict.Reasons = append(verdict.Reasons, "high_bot_probability")
	case verdict.Score < 55:
		verdict.IsSuspicious = true
		verdict.Profile = "suspicious"
		verdict.Reasons = append(verdict.Reasons, "suspicious_pattern")
	default:
		verdict.Profile = "human"
	}

	p.BotProbability = 1.0 - (verdict.Score / 100.0)
	return verdict
}

// analyzeTimingRegularity checks if request timing is too regular (bot-like)
func (p *BehaviorProfile) analyzeTimingRegularity() float64 {
	if len(p.IntervalSamples) < 10 {
		return 0
	}

	avg := meanFloat(p.IntervalSamples)
	if avg == 0 {
		return 100 // Zero interval = automated flood
	}

	stddev := stddevFloat(p.IntervalSamples, avg)
	cv := stddev / avg // Coefficient of variation

	// Humans: high CV (0.5-2.0+), Bots: low CV (0.0-0.3)
	if cv < 0.05 {
		return 100 // Almost perfectly regular = definitely bot
	}
	if cv < 0.15 {
		return 80
	}
	if cv < 0.30 {
		return 50
	}
	if cv < 0.50 {
		return 20
	}
	return 0 // Very irregular = likely human
}

// analyzeURLEntropy measures URL request distribution
func (p *BehaviorProfile) analyzeURLEntropy() float64 {
	if len(p.URLs) == 0 {
		return 50
	}

	total := float64(0)
	for _, count := range p.URLs {
		total += float64(count)
	}

	// Shannon entropy
	entropy := 0.0
	for _, count := range p.URLs {
		prob := float64(count) / total
		if prob > 0 {
			entropy -= prob * math.Log2(prob)
		}
	}

	// Max possible entropy for this number of unique URLs
	maxEntropy := math.Log2(float64(len(p.URLs)))
	if maxEntropy == 0 {
		return 80 // Only one URL → suspicious
	}

	normalizedEntropy := entropy / maxEntropy

	// Very low entropy = hammering same URLs → bot
	if normalizedEntropy < 0.2 {
		return 90
	}
	if normalizedEntropy < 0.4 {
		return 60
	}
	if normalizedEntropy < 0.6 {
		return 30
	}
	return 0
}

// analyzeDiversity checks request method/resource diversity
func (p *BehaviorProfile) analyzeDiversity() float64 {
	penalty := 0.0

	// Only GET, no other methods → slightly suspicious
	if len(p.Methods) == 1 {
		penalty += 20
	}

	// No static resources (real browsers load CSS/JS/images)
	if p.StaticReqs == 0 && p.TotalReqs > 20 {
		penalty += 40
	}

	// Only API endpoints → could be bot
	if p.DynamicReqs > 0 && p.StaticReqs == 0 && p.APIEndpoints > 0 {
		penalty += 30
	}

	// Ratio of unique URLs to total requests
	uniqueRatio := float64(len(p.URLs)) / float64(p.TotalReqs)
	if p.TotalReqs > 50 && uniqueRatio < 0.05 {
		penalty += 40 // Very few unique URLs relative to total requests
	}

	if penalty > 100 {
		penalty = 100
	}
	return penalty
}

// analyzeSpeed checks request speed
func (p *BehaviorProfile) analyzeSpeed() float64 {
	elapsed := time.Since(p.FirstSeen).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}

	rps := float64(p.TotalReqs) / elapsed

	if rps > 100 {
		return 100 // Extreme speed
	}
	if rps > 50 {
		return 80
	}
	if rps > 20 {
		return 60
	}
	if rps > 10 {
		return 30
	}
	return 0
}

// analyzeErrorPattern checks for scanning patterns
func (p *BehaviorProfile) analyzeErrorPattern() float64 {
	if p.TotalReqs < 10 {
		return 0
	}

	total4xx := 0
	for code, count := range p.StatusCodes {
		if code >= 400 && code < 500 {
			total4xx += count
		}
	}

	errorRate := float64(total4xx) / float64(p.TotalReqs)

	// High 4xx rate = scanning/probing
	if errorRate > 0.5 {
		return 100
	}
	if errorRate > 0.3 {
		return 70
	}
	if errorRate > 0.15 {
		return 40
	}
	return 0
}

// analyzeUAConsistency checks user agent patterns
func (p *BehaviorProfile) analyzeUAConsistency() float64 {
	penalty := 0.0

	// Multiple different UAs from same IP → suspicious
	if len(p.UserAgents) > 3 {
		penalty += 60
	}

	return penalty
}

// Cleanup removes stale profiles
func (ba *BehaviorAnalyzer) Cleanup(maxAge time.Duration) {
	now := time.Now()
	ba.profiles.Range(func(key, value interface{}) bool {
		p := value.(*BehaviorProfile)
		if now.Sub(p.LastSeen) > maxAge {
			ba.profiles.Delete(key)
		}
		return true
	})
}

// --- Helpers ---

func normalizeURL(url string) string {
	// Strip query parameters for pattern analysis
	if idx := strings.Index(url, "?"); idx > 0 {
		return url[:idx]
	}
	return url
}

func isStaticResource(url string) bool {
	exts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico", ".webp"}
	lower := strings.ToLower(url)
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func isAPIEndpoint(url string) bool {
	return strings.HasPrefix(url, "/api/") || strings.HasPrefix(url, "/v1/") || strings.HasPrefix(url, "/v2/")
}

func meanFloat(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

func stddevFloat(data []float64, avg float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range data {
		diff := v - avg
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(data)))
}
