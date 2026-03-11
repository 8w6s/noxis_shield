package policy

// Action defines what happens when a rule matches.
type Action string

const (
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionLog       Action = "log"
)

// Rule represents a single user-defined or system-defined traffic policy.
type Rule struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"` // e.g., 'req.Path startsWith "/wp-login"'
	Action     Action `yaml:"action"`     // block, challenge, or log
	Severity   int    `yaml:"severity"`   // Optional. How much signal score to emit (e.g., 50)
	Enabled    bool   `yaml:"enabled"`
}
