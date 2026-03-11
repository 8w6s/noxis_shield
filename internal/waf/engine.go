package waf

import (
	"regexp"
	"strings"
	"sync"

	"github.com/8w6s/noxis/config"
	"github.com/valyala/fasthttp"
)

// Engine is the WAF rules engine adapted for Noxis
type Engine struct {
	cfg       *config.AppConfig
	rules     []*Rule
	ruleIndex map[string]*Rule
	mu        sync.RWMutex
	stats     EngineStats
}

// Rule represents a single WAF rule
type Rule struct {
	ID       string
	Name     string
	Category string
	Severity string
	Targets  []string // URL, ARGS, HEADERS, COOKIES, UA, METHOD
	Operator string   // rx (regex), eq, contains, beginsWith, endsWith
	Pattern  string
	Compiled *regexp.Regexp
	Action   string
	Enabled  bool
	Paranoia int
}

// InspectResult holds all matches for a request
type InspectResult struct {
	Blocked         bool
	Score           int
	TopRule         string
	TopRuleSeverity string // "low", "medium", "high", "critical"
}

// EngineStats tracks WAF engine statistics
type EngineStats struct {
	mu             sync.Mutex
	TotalInspected int64
	TotalBlocked   int64
	TotalMatched   int64
	RuleHits       map[string]int64
}

// NewEngine creates a new WAF rules engine
func NewEngine(cfg *config.AppConfig) *Engine {
	e := &Engine{
		cfg:       cfg,
		ruleIndex: make(map[string]*Rule),
		stats:     EngineStats{RuleHits: make(map[string]int64)},
	}

	if cfg.WAF.Enabled {
		e.loadOWASPRules(cfg.WAF.ParanoiaLevel)
	}

	return e
}

// Inspect inspects a fasthttp request against all loaded rules
func (e *Engine) Inspect(ctx *fasthttp.RequestCtx) *InspectResult {
	if !e.cfg.WAF.Enabled {
		return &InspectResult{Blocked: false}
	}

	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	result := &InspectResult{}

	e.stats.mu.Lock()
	e.stats.TotalInspected++
	e.stats.mu.Unlock()

	// Extract request data once
	reqData := extractRequestData(ctx)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.Paranoia > e.cfg.WAF.ParanoiaLevel {
			continue
		}

		if e.matchRule(rule, reqData) {
			result.Score += severityScore(rule.Severity)

			e.stats.mu.Lock()
			e.stats.TotalMatched++
			e.stats.RuleHits[rule.ID]++
			e.stats.mu.Unlock()

			if rule.Action == "block" || rule.Action == "drop" {
				result.Blocked = true
				result.TopRule = rule.ID
				result.TopRuleSeverity = rule.Severity
				break // Stop on first block action to save CPU
			}
		}
	}

	if result.Blocked {
		e.stats.mu.Lock()
		e.stats.TotalBlocked++
		e.stats.mu.Unlock()
	}

	return result
}

// requestData holds extracted request data for inspection
type requestData struct {
	URL     string
	Path    string
	Query   string
	Method  string
	Headers map[string]string
	Cookies map[string]string
	UA      string
	Args    map[string]string
}

func extractRequestData(ctx *fasthttp.RequestCtx) *requestData {
	rd := &requestData{
		URL:     string(ctx.RequestURI()),
		Path:    string(ctx.Path()),
		Query:   string(ctx.QueryArgs().QueryString()),
		Method:  string(ctx.Method()),
		Headers: make(map[string]string),
		Cookies: make(map[string]string),
		Args:    make(map[string]string),
		UA:      string(ctx.UserAgent()),
	}

	// Extract Headers
	ctx.Request.Header.VisitAll(func(key, value []byte) {
		k := strings.ToLower(string(key))
		v := string(value)
		if existing, ok := rd.Headers[k]; ok {
			rd.Headers[k] = existing + ", " + v
		} else {
			rd.Headers[k] = v
		}
	})

	// Extract Cookies
	ctx.Request.Header.VisitAllCookie(func(key, value []byte) {
		rd.Cookies[string(key)] = string(value)
	})

	// Extract Query Args
	ctx.QueryArgs().VisitAll(func(key, value []byte) {
		rd.Args[string(key)] = string(value)
	})

	// Also extract Post Args if it's a form
	if ctx.IsPost() {
		ctx.PostArgs().VisitAll(func(key, value []byte) {
			rd.Args[string(key)] = string(value)
		})
	}

	return rd
}

func (e *Engine) matchRule(rule *Rule, rd *requestData) bool {
	for _, target := range rule.Targets {
		values := getTargetValues(target, rd)
		for _, val := range values {
			if e.matchOperator(rule, val) {
				return true
			}
		}
	}
	return false
}

func getTargetValues(target string, rd *requestData) []string {
	switch target {
	case "URL":
		return []string{rd.URL}
	case "PATH":
		return []string{rd.Path}
	case "QUERY":
		return []string{rd.Query}
	case "METHOD":
		return []string{rd.Method}
	case "UA":
		return []string{rd.UA}
	case "HEADERS":
		vals := make([]string, 0, len(rd.Headers))
		for _, v := range rd.Headers {
			vals = append(vals, v)
		}
		return vals
	case "ARGS":
		vals := make([]string, 0, len(rd.Args))
		for _, v := range rd.Args {
			vals = append(vals, v)
		}
		return vals
	case "COOKIES":
		vals := make([]string, 0, len(rd.Cookies))
		for _, v := range rd.Cookies {
			vals = append(vals, v)
		}
		return vals
	default:
		return nil
	}
}

func (e *Engine) matchOperator(rule *Rule, value string) bool {
	switch rule.Operator {
	case "rx":
		if rule.Compiled != nil {
			return rule.Compiled.MatchString(value)
		}
		return false
	case "contains":
		return strings.Contains(strings.ToLower(value), strings.ToLower(rule.Pattern))
	case "eq":
		return strings.EqualFold(value, rule.Pattern)
	case "beginsWith":
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(rule.Pattern))
	case "endsWith":
		return strings.HasSuffix(strings.ToLower(value), strings.ToLower(rule.Pattern))
	default:
		return false
	}
}

func severityScore(severity string) int {
	switch severity {
	case "critical":
		return 25
	case "high":
		return 15
	case "medium":
		return 10
	case "low":
		return 5
	default:
		return 1
	}
}
