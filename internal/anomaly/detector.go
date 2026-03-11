package anomaly

import (
	"log"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/8w6s/noxis/internal/defense"
)

// Detector monitors global traffic and identifies volumetric anomalies using Z-Score.
type Detector struct {
	currentRPS      *atomic.Int64
	samples         []float64
	sampleIndex     int
	windowSize      int
	minSamples      int
	zScoreThreshold float64

	mu sync.RWMutex

	// Callbacks
	OnAttackDetected func(rps float64, zscore float64)
	OnAttackResolved func(duration time.Duration)
	OnTick           func(rps float64)

	defenseManager *defense.Manager
	attackStart    time.Time
}

// New creates a new anomaly detector.
func New(baselineWindowMinutes int, zscoreThreshold float64, defManager *defense.Manager) *Detector {
	windowSize := baselineWindowMinutes * 60
	if windowSize <= 0 {
		windowSize = 3600 // Default 1 hour
	}

	d := &Detector{
		currentRPS:      &atomic.Int64{},
		samples:         make([]float64, 0, windowSize),
		sampleIndex:     0,
		windowSize:      windowSize,
		minSamples:      60, // requires at least 1 minute of data to build a baseline
		zScoreThreshold: zscoreThreshold,
		defenseManager:  defManager,
	}

	return d
}

// Start begins the background ticker that calculates Z-Score every second.
func (d *Detector) Start() {
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for range ticker.C {
			d.tick()
		}
	}()
}

// RecordHit is called by the proxy pipeline for every request to increment RPS.
func (d *Detector) RecordHit() {
	d.currentRPS.Add(1)
}

func (d *Detector) tick() {
	rps := float64(d.currentRPS.Swap(0)) // Get and reset the counter atomically

	if d.OnTick != nil {
		d.OnTick(rps)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// 1. Z-Score Calculation (Only if we have enough baseline data)
	if len(d.samples) >= d.minSamples {
		mean := d.calculateMean()
		stddev := d.calculateStdDev(mean)

		// Calculate Z-Score: (Value - Mean) / Standard Deviation
		// Avoid division by zero if stddev is 0 (completely flat traffic)
		zscore := 0.0
		if stddev > 0 {
			zscore = (rps - mean) / stddev
		} else if rps > mean && mean > 0 {
			// If traffic spikes significantly from a flat line, assign an arbitrary high score manually
			zscore = d.zScoreThreshold + 1.0
		}

		// Detect Attack
		if zscore > d.zScoreThreshold {
			currentMode := d.defenseManager.GetMode()
			if currentMode != defense.ModeUnderAttack {
				d.defenseManager.SetMode(defense.ModeUnderAttack, "high anomaly z-score detected")
				d.attackStart = time.Now()
				if d.OnAttackDetected != nil {
					go d.OnAttackDetected(rps, zscore)
				}
			}
		} else {
			// Resolve Attack if it drops back below threshold
			currentMode := d.defenseManager.GetMode()
			if currentMode == defense.ModeUnderAttack {
				d.defenseManager.SetMode(defense.ModeRecovery, "anomaly z-score normalized")
				duration := time.Since(d.attackStart)
				if d.OnAttackResolved != nil {
					go d.OnAttackResolved(duration)
				}

				// Start a cooldown goroutine to eventually move from recovery to normal
				go func() {
					time.Sleep(5 * time.Minute) // 5 minutes recovery cooldown
					if d.defenseManager.GetMode() == defense.ModeRecovery {
						d.defenseManager.SetMode(defense.ModeNormal, "recovery period completed")
					}
				}()
			}
		}
	} else if len(d.samples) == 0 {
		log.Println("[Anomaly] Learning traffic baseline. Alerts suppressed until sufficient data is gathered.")
	}

	// 2. Add current RPS to Rolling Window
	if len(d.samples) < d.windowSize {
		d.samples = append(d.samples, rps)
	} else {
		// Overwrite oldest sample in circular buffer style
		d.samples[d.sampleIndex] = rps
		d.sampleIndex = (d.sampleIndex + 1) % d.windowSize
	}
}

// calculateMean computes the average of all samples
func (d *Detector) calculateMean() float64 {
	sum := 0.0
	for _, v := range d.samples {
		sum += v
	}
	return sum / float64(len(d.samples))
}

// calculateStdDev computes the population standard deviation
func (d *Detector) calculateStdDev(mean float64) float64 {
	var varianceSum float64
	for _, v := range d.samples {
		diff := v - mean
		varianceSum += diff * diff
	}
	variance := varianceSum / float64(len(d.samples))
	return math.Sqrt(variance)
}
