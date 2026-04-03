package enrichment

import (
	"math"
	"sort"
	"time"
)

const (
	// DefaultMinBeaconPackets is the minimum number of packets required before
	// beacon analysis is attempted. Fewer packets cannot produce a reliable
	// inter-arrival time distribution.
	DefaultMinBeaconPackets = 5

	// DefaultMaxBeaconJitter is the coefficient of variation (stddev/mean)
	// threshold below which a flow is flagged as a beacon candidate.
	// Regular C2 heartbeats have very low jitter (CV < 0.1).
	// Human-driven traffic is irregular (CV >> 0.1).
	DefaultMaxBeaconJitter = 0.1

	// DefaultMinBeaconInterval is the minimum mean inter-arrival time for a
	// flow to be considered for beacon detection. Sub-second intervals are
	// typical of normal TCP behaviour (ACKs, window probes) and would produce
	// too many false positives.
	DefaultMinBeaconInterval = time.Second
)

// BeaconResult holds the outcome of beacon analysis for a single flow.
type BeaconResult struct {
	IsBeacon bool    // true if inter-arrival jitter is below the threshold
	Interval float64 // mean inter-arrival time in seconds
	Jitter   float64 // coefficient of variation (stddev/mean); 0 if undetermined
}

// BeaconDetector accumulates per-packet timestamps per flow and detects
// C2-style heartbeat patterns by analysing inter-arrival time regularity.
//
// A flow is flagged as a beacon candidate when:
//  1. It has at least minPackets timestamps
//  2. Its mean inter-arrival time is >= minInterval (filters TCP housekeeping)
//  3. Its coefficient of variation (stddev/mean) is <= maxJitter
//
// Feed timestamps with Update; retrieve results with Analyze or Results.
type BeaconDetector struct {
	timestamps  map[string][]time.Time
	minPackets  int
	maxJitter   float64
	minInterval time.Duration
}

// NewBeaconDetector creates a detector. Pass 0 for any parameter to use its default.
func NewBeaconDetector(minPackets int, maxJitter float64, minInterval time.Duration) *BeaconDetector {
	if minPackets <= 0 {
		minPackets = DefaultMinBeaconPackets
	}
	if maxJitter <= 0 {
		maxJitter = DefaultMaxBeaconJitter
	}
	if minInterval <= 0 {
		minInterval = DefaultMinBeaconInterval
	}
	return &BeaconDetector{
		timestamps:  make(map[string][]time.Time),
		minPackets:  minPackets,
		maxJitter:   maxJitter,
		minInterval: minInterval,
	}
}

// Update records a packet timestamp for flowID.
// Empty flowID is silently ignored.
func (d *BeaconDetector) Update(flowID string, ts time.Time) {
	if flowID == "" {
		return
	}
	d.timestamps[flowID] = append(d.timestamps[flowID], ts)
}

// Analyze returns the BeaconResult for flowID.
// Returns a zero BeaconResult if the flow has fewer than minPackets timestamps.
func (d *BeaconDetector) Analyze(flowID string) BeaconResult {
	return d.analyze(d.timestamps[flowID])
}

// Results runs Analyze over every flow and returns a map of flowID → BeaconResult.
func (d *BeaconDetector) Results() map[string]BeaconResult {
	out := make(map[string]BeaconResult, len(d.timestamps))
	for id, ts := range d.timestamps {
		out[id] = d.analyze(ts)
	}
	return out
}

// analyze computes the BeaconResult for a slice of timestamps.
func (d *BeaconDetector) analyze(ts []time.Time) BeaconResult {
	if len(ts) < d.minPackets {
		return BeaconResult{}
	}

	// Defensive sort — packets should arrive in order but PCAP files may
	// have minor reordering.
	sorted := make([]time.Time, len(ts))
	copy(sorted, ts)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Before(sorted[j])
	})

	// Inter-arrival times in seconds.
	iats := make([]float64, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		iats[i-1] = sorted[i].Sub(sorted[i-1]).Seconds()
	}

	mean := iatMean(iats)

	// Flows with a mean IAT below the minimum interval are not candidates —
	// this covers TCP ACKs, window probes, and other sub-second housekeeping.
	// Guard mean == 0 explicitly to prevent division by zero.
	if mean == 0 || mean < d.minInterval.Seconds() {
		return BeaconResult{Interval: mean}
	}

	stddev := iatStddev(iats, mean)
	cv := stddev / mean

	return BeaconResult{
		IsBeacon: cv <= d.maxJitter,
		Interval: mean,
		Jitter:   cv,
	}
}

// iatMean returns the arithmetic mean of vals. Returns 0 for empty input.
func iatMean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// iatStddev returns the population standard deviation of vals given its mean.
// Returns 0 for empty input.
func iatStddev(vals []float64, mean float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sumSq float64
	for _, v := range vals {
		diff := v - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(vals)))
}
