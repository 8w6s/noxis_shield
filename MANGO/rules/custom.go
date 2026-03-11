package rules

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"

	"mango-waf/logger"
)

// CustomRuleFile represents a YAML custom rules file
type CustomRuleFile struct {
	Rules []CustomRuleEntry `yaml:"rules"`
}

// CustomRuleEntry represents a custom rule in YAML format
type CustomRuleEntry struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Category    string   `yaml:"category"`
	Severity    string   `yaml:"severity"`
	Targets     []string `yaml:"targets"`
	Operator    string   `yaml:"operator"`
	Pattern     string   `yaml:"pattern"`
	Action      string   `yaml:"action"`
	Enabled     bool     `yaml:"enabled"`
	Paranoia    int      `yaml:"paranoia"`
	Tags        []string `yaml:"tags"`
}

// LoadCustomRules loads custom rules from a YAML file
func (e *Engine) LoadCustomRules(path string) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read custom rules: %w", err)
	}

	var file CustomRuleFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse custom rules: %w", err)
	}

	loaded := 0
	for _, entry := range file.Rules {
		rule := &Rule{
			ID:          entry.ID,
			Name:        entry.Name,
			Description: entry.Description,
			Category:    entry.Category,
			Severity:    entry.Severity,
			Targets:     entry.Targets,
			Operator:    entry.Operator,
			Pattern:     entry.Pattern,
			Action:      entry.Action,
			Enabled:     entry.Enabled,
			Paranoia:    entry.Paranoia,
			Tags:        entry.Tags,
		}

		if rule.Paranoia == 0 {
			rule.Paranoia = 1
		}
		if rule.Action == "" {
			rule.Action = "block"
		}

		if err := e.AddRule(rule); err != nil {
			logger.Warn("Failed to load custom rule", "id", entry.ID, "error", err)
			continue
		}
		loaded++
	}

	logger.Info("Custom rules loaded", "path", path, "count", loaded)
	return nil
}

// EnableRule enables a rule by ID
func (e *Engine) EnableRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rule, ok := e.ruleIndex[id]; ok {
		rule.Enabled = true
		return true
	}
	return false
}

// DisableRule disables a rule by ID
func (e *Engine) DisableRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rule, ok := e.ruleIndex[id]; ok {
		rule.Enabled = false
		return true
	}
	return false
}

// GetRules returns all loaded rules
func (e *Engine) GetRules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Rule, len(e.rules))
	copy(result, e.rules)
	return result
}

// GetRule returns a rule by ID
func (e *Engine) GetRule(id string) *Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ruleIndex[id]
}

// RemoveRule removes a rule by ID
func (e *Engine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.ruleIndex, id)
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// CreateQuickRule creates a simple blocking rule from minimal parameters
func CreateQuickRule(id, pattern, target, category string) *Rule {
	compiled, _ := regexp.Compile("(?i)" + pattern)
	return &Rule{
		ID:       id,
		Name:     "Quick Rule: " + id,
		Category: category,
		Severity: "high",
		Phase:    1,
		Targets:  []string{target},
		Operator: "rx",
		Pattern:  pattern,
		Compiled: compiled,
		Action:   "block",
		Enabled:  true,
		Paranoia: 1,
	}
}
