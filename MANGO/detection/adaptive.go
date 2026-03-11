package detection

import (
	"math"
	"sync"
	"time"

	"mango-waf/logger"
)

// AdaptiveLearner learns traffic patterns and adjusts protection dynamically
type AdaptiveLearner struct {
	mu sync.RWMutex

	// Hourly traffic profiles (24 hours)
	hourlyProfiles [24]*HourlyProfile

	// Day-of-week factor
	weekdayFactors [7]float64

	// Learned thresholds
	LearnedRPSThreshold  float64
	LearnedConnThreshold float64
	LearnedBotBaseline   float64

	// Learning state
	DataPoints      int64
	LearningDays    int
	IsCalibrated    bool
	LastCalibration time.Time

	// Confidence (0.0 - 1.0)
	Confidence float64
}

// HourlyProfile stores typical traffic for one hour of the day
type HourlyProfile struct {
	mu         sync.Mutex
	AvgRPS     float64
	MaxRPS     float64
	MinRPS     float64
	StddevRPS  float64
	AvgConns   float64
	AvgBotRate float64
	Samples    []float64
	MaxSamples int
}

// AdaptiveDecision is a real-time decision from the learner
type AdaptiveDecision struct {
	RPSThreshold    int64   // Current recommended RPS threshold
	ChallengeLevel  int     // 0=off, 1=js, 2=captcha
	RateLimitFactor float64 // Multiplier for rate limit (1.0 = normal)
	EmergencyMode   bool
	Reason          string
}

// NewAdaptiveLearner creates a new adaptive learner
func NewAdaptiveLearner() *AdaptiveLearner {
	al := &AdaptiveLearner{}

	for i := range al.hourlyProfiles {
		al.hourlyProfiles[i] = &HourlyProfile{
			MaxSamples: 720, // 12 hours of per-minute samples
			MinRPS:     math.MaxFloat64,
		}
	}

	// Default weekday factors
	for i := range al.weekdayFactors {
		al.weekdayFactors[i] = 1.0
	}

	return al
}

// RecordSample records a traffic sample for learning
func (al *AdaptiveLearner) RecordSample(rps float64, conns float64, botRate float64) {
	now := time.Now()
	hour := now.Hour()

	profile := al.hourlyProfiles[hour]
	profile.mu.Lock()
	defer profile.mu.Unlock()

	// Add sample
	if len(profile.Samples) >= profile.MaxSamples {
		profile.Samples = profile.Samples[1:] // Sliding window
	}
	profile.Samples = append(profile.Samples, rps)

	// Update stats
	if len(profile.Samples) > 0 {
		profile.AvgRPS = meanFloat(profile.Samples)
		profile.StddevRPS = stddevFloat(profile.Samples, profile.AvgRPS)
		if rps > profile.MaxRPS {
			profile.MaxRPS = rps
		}
		if rps < profile.MinRPS {
			profile.MinRPS = rps
		}
	}

	// Track connections and bot rate with exponential moving average
	alpha := 0.01 // Slow learning
	profile.AvgConns = profile.AvgConns*(1-alpha) + conns*alpha
	profile.AvgBotRate = profile.AvgBotRate*(1-alpha) + botRate*alpha

	al.mu.Lock()
	al.DataPoints++

	// Check if we have enough data to be calibrated
	if al.DataPoints > 3600 && !al.IsCalibrated { // 1 hour of per-second data
		al.calibrate()
	}

	// Re-calibrate every 6 hours
	if al.IsCalibrated && time.Since(al.LastCalibration) > 6*time.Hour {
		al.calibrate()
	}
	al.mu.Unlock()
}

// calibrate updates learned thresholds from accumulated data
func (al *AdaptiveLearner) calibrate() {
	// Calculate overall thresholds across all hours
	var allAvgs []float64
	var allMaxes []float64

	for _, profile := range al.hourlyProfiles {
		if len(profile.Samples) > 10 {
			allAvgs = append(allAvgs, profile.AvgRPS)
			allMaxes = append(allMaxes, profile.MaxRPS)
		}
	}

	if len(allAvgs) == 0 {
		return
	}

	overallAvg := meanFloat(allAvgs)
	overallStddev := stddevFloat(allAvgs, overallAvg)
	overallMax := 0.0
	for _, m := range allMaxes {
		if m > overallMax {
			overallMax = m
		}
	}

	// RPS threshold = max(3 * stddev above mean, 2 * peak)
	al.LearnedRPSThreshold = math.Max(
		overallAvg+3*overallStddev,
		overallMax*2,
	)

	// Minimum threshold
	if al.LearnedRPSThreshold < 100 {
		al.LearnedRPSThreshold = 100
	}

	al.IsCalibrated = true
	al.LastCalibration = time.Now()
	al.LearningDays++

	// Confidence grows with data
	al.Confidence = math.Min(1.0, float64(al.DataPoints)/86400.0) // 1 day = full confidence

	logger.Info("Adaptive learner calibrated",
		"rps_threshold", al.LearnedRPSThreshold,
		"overall_avg", overallAvg,
		"confidence", al.Confidence,
		"data_points", al.DataPoints,
	)
}

// GetDecision returns an adaptive protection decision based on current traffic
func (al *AdaptiveLearner) GetDecision(currentRPS float64) *AdaptiveDecision {
	al.mu.RLock()
	defer al.mu.RUnlock()

	decision := &AdaptiveDecision{
		RPSThreshold:    1000, // Default
		ChallengeLevel:  0,
		RateLimitFactor: 1.0,
	}

	if !al.IsCalibrated {
		decision.Reason = "not_calibrated"
		return decision
	}

	decision.RPSThreshold = int64(al.LearnedRPSThreshold)

	// Get expected profile for current hour
	now := time.Now()
	hour := now.Hour()
	profile := al.hourlyProfiles[hour]

	expectedRPS := profile.AvgRPS
	if expectedRPS == 0 {
		expectedRPS = al.LearnedRPSThreshold / 3
	}

	ratio := currentRPS / expectedRPS

	switch {
	case ratio > 20:
		decision.EmergencyMode = true
		decision.ChallengeLevel = 2
		decision.RateLimitFactor = 0.1
		decision.Reason = "extreme_spike"
	case ratio > 10:
		decision.ChallengeLevel = 2
		decision.RateLimitFactor = 0.25
		decision.Reason = "major_spike"
	case ratio > 5:
		decision.ChallengeLevel = 1
		decision.RateLimitFactor = 0.5
		decision.Reason = "significant_spike"
	case ratio > 3:
		decision.ChallengeLevel = 1
		decision.RateLimitFactor = 0.75
		decision.Reason = "moderate_spike"
	case ratio > 2:
		decision.RateLimitFactor = 0.9
		decision.Reason = "minor_spike"
	case ratio < 0.3:
		// Very low traffic — could be calm or could be partial outage
		decision.RateLimitFactor = 2.0 // Be more lenient
		decision.Reason = "low_traffic"
	default:
		decision.Reason = "normal"
	}

	return decision
}

// GetExpectedRPS returns expected RPS for current time
func (al *AdaptiveLearner) GetExpectedRPS() float64 {
	hour := time.Now().Hour()
	profile := al.hourlyProfiles[hour]
	return profile.AvgRPS
}

// GetStats returns learner statistics
func (al *AdaptiveLearner) GetStats() map[string]interface{} {
	al.mu.RLock()
	defer al.mu.RUnlock()

	return map[string]interface{}{
		"calibrated":     al.IsCalibrated,
		"confidence":     al.Confidence,
		"data_points":    al.DataPoints,
		"rps_threshold":  al.LearnedRPSThreshold,
		"conn_threshold": al.LearnedConnThreshold,
		"learning_days":  al.LearningDays,
	}
}
