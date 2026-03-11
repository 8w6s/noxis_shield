package intelligence

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

// ThreatFeedManager aggregates threat intelligence from multiple feeds
type ThreatFeedManager struct {
	cfg        *config.Config
	knownBad   sync.Map // map[string]ThreatEntry
	feedStats  FeedStats
	httpClient *http.Client
	mu         sync.RWMutex
}

// ThreatEntry holds info about a known threat
type ThreatEntry struct {
	IP       string
	Source   string
	Category string // malware, spam, botnet, scanner, bruteforce
	AddedAt  time.Time
}

// FeedStats tracks feed update statistics
type FeedStats struct {
	LastUpdate   time.Time
	TotalEntries int
	FeedErrors   int
	FeedSources  int
}

// Feed represents a threat intelligence feed
type Feed struct {
	Name     string
	URL      string
	Category string
	Parser   string // "line" or "csv"
	Enabled  bool
}

// NewThreatFeedManager creates a new threat feed manager
func NewThreatFeedManager(cfg *config.Config) *ThreatFeedManager {
	return &ThreatFeedManager{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DefaultFeeds returns the list of built-in threat intelligence feeds
func DefaultFeeds() []Feed {
	return []Feed{
		{
			Name:     "FireHOL Level 1",
			URL:      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
			Category: "malware",
			Parser:   "line",
			Enabled:  true,
		},
		{
			Name:     "Spamhaus DROP",
			URL:      "https://www.spamhaus.org/drop/drop.txt",
			Category: "spam",
			Parser:   "line",
			Enabled:  true,
		},
		{
			Name:     "Spamhaus EDROP",
			URL:      "https://www.spamhaus.org/drop/edrop.txt",
			Category: "spam",
			Parser:   "line",
			Enabled:  true,
		},
		{
			Name:     "Blocklist.de All",
			URL:      "https://lists.blocklist.de/lists/all.txt",
			Category: "bruteforce",
			Parser:   "line",
			Enabled:  true,
		},
		{
			Name:     "CI Army Badguys",
			URL:      "https://cinsscore.com/list/ci-badguys.txt",
			Category: "scanner",
			Parser:   "line",
			Enabled:  true,
		},
		{
			Name:     "Emerging Threats Compromised IPs",
			URL:      "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			Category: "botnet",
			Parser:   "line",
			Enabled:  true,
		},
		{
			Name:     "TOR Exit Nodes",
			URL:      "https://check.torproject.org/torbulkexitlist",
			Category: "anonymizer",
			Parser:   "line",
			Enabled:  true,
		},
		{
			Name:     "DShield Top Attackers",
			URL:      "https://feeds.dshield.org/block.txt",
			Category: "scanner",
			Parser:   "line",
			Enabled:  true,
		},
	}
}

// IsKnownThreat checks if an IP is in any threat feed
func (tf *ThreatFeedManager) IsKnownThreat(ip string) bool {
	_, ok := tf.knownBad.Load(ip)
	return ok
}

// GetThreatInfo returns threat details for an IP
func (tf *ThreatFeedManager) GetThreatInfo(ip string) *ThreatEntry {
	if v, ok := tf.knownBad.Load(ip); ok {
		entry := v.(ThreatEntry)
		return &entry
	}
	return nil
}

// StartPeriodicUpdate starts periodic feed updates
func (tf *ThreatFeedManager) StartPeriodicUpdate(interval time.Duration) {
	// Initial load
	tf.UpdateAll()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		tf.UpdateAll()
	}
}

// UpdateAll updates all threat feeds
func (tf *ThreatFeedManager) UpdateAll() {
	feeds := DefaultFeeds()
	totalNew := 0
	errors := 0

	logger.Info("Updating threat feeds", "count", len(feeds))

	for _, feed := range feeds {
		if !feed.Enabled {
			continue
		}

		count, err := tf.fetchFeed(feed)
		if err != nil {
			logger.Warn("Feed update failed", "feed", feed.Name, "error", err)
			errors++
			continue
		}
		totalNew += count
		logger.Debug("Feed updated", "feed", feed.Name, "entries", count)
	}

	tf.mu.Lock()
	tf.feedStats.LastUpdate = time.Now()
	tf.feedStats.FeedErrors = errors
	tf.feedStats.FeedSources = len(feeds)
	tf.mu.Unlock()

	// Count total entries
	total := 0
	tf.knownBad.Range(func(_, _ interface{}) bool {
		total++
		return true
	})
	tf.mu.Lock()
	tf.feedStats.TotalEntries = total
	tf.mu.Unlock()

	logger.Info("Threat feeds updated",
		"new_entries", totalNew,
		"total", total,
		"errors", errors,
	)
}

// fetchFeed downloads and parses a single feed
func (tf *ThreatFeedManager) fetchFeed(feed Feed) (int, error) {
	resp, err := tf.httpClient.Get(feed.URL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("feed %s returned status %d", feed.Name, resp.StatusCode)
	}

	count := 0
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Extract IP/CIDR from the line
		ip := extractIPFromLine(line)
		if ip == "" {
			continue
		}

		tf.knownBad.Store(ip, ThreatEntry{
			IP:       ip,
			Source:   feed.Name,
			Category: feed.Category,
			AddedAt:  time.Now(),
		})
		count++
	}

	return count, scanner.Err()
}

// extractIPFromLine parses an IP address from a feed line
func extractIPFromLine(line string) string {
	// Handle lines with comments at end
	if idx := strings.Index(line, "#"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if idx := strings.Index(line, ";"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
	}

	// Handle tab/space separated (DShield format: "start\tend\tcount")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}

	candidate := fields[0]

	// Validate as IP or CIDR
	if net.ParseIP(candidate) != nil {
		return candidate
	}
	if _, _, err := net.ParseCIDR(candidate); err == nil {
		return candidate
	}

	return ""
}

// GetStats returns feed statistics
func (tf *ThreatFeedManager) GetStats() FeedStats {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.feedStats
}

// ManualAdd manually adds an IP to threat list
func (tf *ThreatFeedManager) ManualAdd(ip, category, source string) {
	tf.knownBad.Store(ip, ThreatEntry{
		IP:       ip,
		Source:   source,
		Category: category,
		AddedAt:  time.Now(),
	})
}

// Remove removes an IP from threat list
func (tf *ThreatFeedManager) Remove(ip string) {
	tf.knownBad.Delete(ip)
}
