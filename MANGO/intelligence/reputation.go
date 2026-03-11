package intelligence

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

// ReputationResult holds IP reputation data
type ReputationResult struct {
	IP           string
	AbuseScore   int     // 0-100, higher = more abusive
	TrustLevel   float64 // 0.0-1.0
	IsKnownBad   bool
	IsProxy      bool
	IsTor        bool
	IsVPN        bool
	IsDatacenter bool
	TotalReports int
	LastReported time.Time
	Source       string
	CachedAt     time.Time
}

// ReputationEngine checks IP reputation across multiple providers
type ReputationEngine struct {
	cfg        *config.Config
	cache      sync.Map // map[string]*ReputationResult
	httpClient *http.Client
}

// NewReputationEngine creates a new reputation engine
func NewReputationEngine(cfg *config.Config) *ReputationEngine {
	return &ReputationEngine{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Check checks IP reputation (with caching)
func (re *ReputationEngine) Check(ip string) *ReputationResult {
	// Check cache first
	if cached, ok := re.cache.Load(ip); ok {
		rep := cached.(*ReputationResult)
		if time.Since(rep.CachedAt) < re.cfg.Intelligence.IPReputation.CacheTTL {
			return rep
		}
		// Cache expired, will re-query
	}

	// Query providers in priority order
	var result *ReputationResult

	// 1. AbuseIPDB
	if re.cfg.Intelligence.IPReputation.AbuseIPDBKey != "" {
		result = re.queryAbuseIPDB(ip)
	}

	// 2. If no result, create a basic one
	if result == nil {
		result = &ReputationResult{
			IP:         ip,
			AbuseScore: 0,
			TrustLevel: 0.7,
			Source:     "default",
		}
	}

	// Cache result
	result.CachedAt = time.Now()
	re.cache.Store(ip, result)

	return result
}

// queryAbuseIPDB queries the AbuseIPDB API
func (re *ReputationEngine) queryAbuseIPDB(ip string) *ReputationResult {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose=true", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Key", re.cfg.Intelligence.IPReputation.AbuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := re.httpClient.Do(req)
	if err != nil {
		logger.Debug("AbuseIPDB query failed", "ip", ip, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		logger.Debug("AbuseIPDB non-200", "ip", ip, "status", resp.StatusCode)
		return nil
	}

	var apiResp struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			IsPublic             bool   `json:"isPublic"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			UsageType            string `json:"usageType"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
			TotalReports         int    `json:"totalReports"`
			NumDistinctUsers     int    `json:"numDistinctUsers"`
			LastReportedAt       string `json:"lastReportedAt"`
			IsTor                bool   `json:"isTor"`
			IsWhitelisted        bool   `json:"isWhitelisted"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		logger.Debug("AbuseIPDB decode failed", "ip", ip, "error", err)
		return nil
	}

	d := apiResp.Data
	result := &ReputationResult{
		IP:           ip,
		AbuseScore:   d.AbuseConfidenceScore,
		TrustLevel:   float64(100-d.AbuseConfidenceScore) / 100.0,
		IsKnownBad:   d.AbuseConfidenceScore > 50,
		IsTor:        d.IsTor,
		TotalReports: d.TotalReports,
		Source:       "abuseipdb",
	}

	// Detect datacenter/proxy from usage type
	usageType := d.UsageType
	switch usageType {
	case "Data Center/Web Hosting/Transit":
		result.IsDatacenter = true
	case "Fixed Line ISP":
		// Residential — good
	case "Mobile ISP":
		// Mobile — okay
	case "Content Delivery Network":
		result.IsDatacenter = true
	case "Search Engine Spider":
		// Could be legitimate
	case "Reserved":
		// Internal
	}

	// Parse last reported time
	if d.LastReportedAt != "" {
		t, err := time.Parse(time.RFC3339, d.LastReportedAt)
		if err == nil {
			result.LastReported = t
		}
	}

	logger.Debug("AbuseIPDB result",
		"ip", ip,
		"abuse_score", d.AbuseConfidenceScore,
		"reports", d.TotalReports,
		"tor", d.IsTor,
		"usage", d.UsageType,
	)

	return result
}

// CleanupCache removes expired cache entries
func (re *ReputationEngine) CleanupCache() {
	ttl := re.cfg.Intelligence.IPReputation.CacheTTL
	re.cache.Range(func(key, value interface{}) bool {
		rep := value.(*ReputationResult)
		if time.Since(rep.CachedAt) > ttl {
			re.cache.Delete(key)
		}
		return true
	})
}

// CacheStats returns cache statistics
func (re *ReputationEngine) CacheStats() int {
	count := 0
	re.cache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
