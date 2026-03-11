package signals

// Default signal weights per source and severity.
// Handlers may override these, but these constants serve as canonical defaults.

const (
	// WAF weights
	WeightWAFLow      = 5
	WeightWAFMedium   = 10
	WeightWAFHigh     = 20
	WeightWAFCritical = 40

	// Rate limiter weights
	WeightRateLimitViolation = 15
	WeightSubnetPressure     = 5

	// Challenge weights
	WeightChallengeFail = 30
	WeightChallengePass = -5 // reward for solving correctly

	// Reputation / behavioral weights
	WeightReputationAbuse    = 25
	WeightReputationCritical = 50

	// Cluster-imported signal weights
	WeightClusterLow    = 5
	WeightClusterMedium = 10
	WeightClusterHigh   = 20
)

// SeverityWeight maps a Severity level to a default weight for modules that
// don't hardcode a specific weight (e.g. WAF uses rule severity as input).
func SeverityWeight(s Severity) int {
	switch s {
	case SeverityLow:
		return WeightWAFLow
	case SeverityMedium:
		return WeightWAFMedium
	case SeverityHigh:
		return WeightWAFHigh
	case SeverityCritical:
		return WeightWAFCritical
	default:
		return WeightWAFMedium
	}
}
