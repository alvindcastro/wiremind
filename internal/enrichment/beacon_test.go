package enrichment

import (
	"math"
	"testing"
	"time"
)

// makeTimestamps builds a slice of n timestamps starting at base,
// each separated by interval plus an optional jitter (in seconds).
// jitterFractions[i] is added to the i-th interval as a fraction of interval.
// If jitterFractions is nil or shorter than n-1, missing values default to 0.
func makeTimestamps(n int, base time.Time, interval time.Duration, jitterFractions []float64) []time.Time {
	ts := make([]time.Time, n)
	ts[0] = base
	for i := 1; i < n; i++ {
		jitter := 0.0
		if i-1 < len(jitterFractions) {
			jitter = jitterFractions[i-1]
		}
		delta := float64(interval) * (1 + jitter)
		ts[i] = ts[i-1].Add(time.Duration(delta))
	}
	return ts
}

// ---------------------------------------------------------------------------
// Constructor defaults
// ---------------------------------------------------------------------------

func TestNewBeaconDetector_Defaults(t *testing.T) {
	d := NewBeaconDetector(0, 0, 0)
	if d.minPackets != DefaultMinBeaconPackets {
		t.Errorf("minPackets: got %d want %d", d.minPackets, DefaultMinBeaconPackets)
	}
	if d.maxJitter != DefaultMaxBeaconJitter {
		t.Errorf("maxJitter: got %f want %f", d.maxJitter, DefaultMaxBeaconJitter)
	}
	if d.minInterval != DefaultMinBeaconInterval {
		t.Errorf("minInterval: got %v want %v", d.minInterval, DefaultMinBeaconInterval)
	}
}

// ---------------------------------------------------------------------------
// Not enough packets
// ---------------------------------------------------------------------------

func TestAnalyze_TooFewPackets_NoBeacon(t *testing.T) {
	d := NewBeaconDetector(5, 0.1, time.Second)
	base := time.Unix(0, 0)

	// Only 4 timestamps — below minPackets of 5
	for _, ts := range makeTimestamps(4, base, 30*time.Second, nil) {
		d.Update("flow1", ts)
	}

	result := d.Analyze("flow1")
	if result.IsBeacon {
		t.Error("IsBeacon: got true want false for too-few packets")
	}
	if result.Interval != 0 {
		t.Errorf("Interval: got %f want 0 for too-few packets", result.Interval)
	}
}

func TestAnalyze_UnknownFlow_ZeroResult(t *testing.T) {
	d := NewBeaconDetector(0, 0, 0)
	result := d.Analyze("nonexistent")
	if result.IsBeacon || result.Interval != 0 || result.Jitter != 0 {
		t.Errorf("expected zero BeaconResult for unknown flow, got %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Perfect beacon (zero jitter)
// ---------------------------------------------------------------------------

func TestAnalyze_PerfectBeacon(t *testing.T) {
	d := NewBeaconDetector(5, 0.1, time.Second)
	base := time.Unix(1000, 0)
	interval := 30 * time.Second

	for _, ts := range makeTimestamps(10, base, interval, nil) {
		d.Update("c2-flow", ts)
	}

	result := d.Analyze("c2-flow")
	if !result.IsBeacon {
		t.Errorf("IsBeacon: got false want true for perfect 30s beacon")
	}
	if !approxEqual(result.Interval, 30.0, 0.001) {
		t.Errorf("Interval: got %f want 30.0", result.Interval)
	}
	if result.Jitter != 0 {
		t.Errorf("Jitter: got %f want 0 for perfect beacon", result.Jitter)
	}
}

// ---------------------------------------------------------------------------
// Low jitter — still a beacon
// ---------------------------------------------------------------------------

func TestAnalyze_LowJitter_IsBeacon(t *testing.T) {
	d := NewBeaconDetector(5, 0.1, time.Second)
	base := time.Unix(0, 0)

	// ±5% jitter around a 60s interval → CV well below 0.1
	jitter := []float64{0.02, -0.03, 0.04, -0.01, 0.03, 0.02, -0.02, 0.01, -0.04}
	for _, ts := range makeTimestamps(10, base, 60*time.Second, jitter) {
		d.Update("low-jitter", ts)
	}

	result := d.Analyze("low-jitter")
	if !result.IsBeacon {
		t.Errorf("IsBeacon: got false, expected true for low-jitter flow (jitter=%f)", result.Jitter)
	}
	if result.Jitter >= DefaultMaxBeaconJitter {
		t.Errorf("Jitter %f should be < threshold %f", result.Jitter, DefaultMaxBeaconJitter)
	}
}

// ---------------------------------------------------------------------------
// High jitter — not a beacon
// ---------------------------------------------------------------------------

func TestAnalyze_HighJitter_NotBeacon(t *testing.T) {
	d := NewBeaconDetector(5, 0.1, time.Second)
	base := time.Unix(0, 0)

	// Irregular human-like browsing: large variance in inter-arrival times
	jitter := []float64{0.5, -0.4, 1.2, -0.6, 0.8, -0.3, 0.9, 1.5, -0.7}
	for _, ts := range makeTimestamps(10, base, 10*time.Second, jitter) {
		d.Update("human-flow", ts)
	}

	result := d.Analyze("human-flow")
	if result.IsBeacon {
		t.Errorf("IsBeacon: got true, expected false for high-jitter flow (jitter=%f)", result.Jitter)
	}
}

// ---------------------------------------------------------------------------
// Below minimum interval — not flagged as beacon
// ---------------------------------------------------------------------------

func TestAnalyze_BelowMinInterval_NotBeacon(t *testing.T) {
	// 1ms interval — typical of TCP ACK storms, not C2 beaconing
	d := NewBeaconDetector(5, 0.1, time.Second)
	base := time.Unix(0, 0)

	for _, ts := range makeTimestamps(10, base, time.Millisecond, nil) {
		d.Update("fast-flow", ts)
	}

	result := d.Analyze("fast-flow")
	if result.IsBeacon {
		t.Errorf("IsBeacon: got true, expected false for sub-second interval flow")
	}
	// Interval should still be populated
	if result.Interval == 0 {
		t.Error("Interval: expected non-zero even when below threshold")
	}
}

// ---------------------------------------------------------------------------
// Empty flowID is ignored
// ---------------------------------------------------------------------------

func TestUpdate_EmptyFlowID_Ignored(t *testing.T) {
	d := NewBeaconDetector(0, 0, 0)
	d.Update("", time.Now())
	if len(d.timestamps) != 0 {
		t.Errorf("expected 0 entries, got %d", len(d.timestamps))
	}
}

// ---------------------------------------------------------------------------
// Unsorted timestamps are handled correctly
// ---------------------------------------------------------------------------

func TestAnalyze_UnsortedTimestamps(t *testing.T) {
	d := NewBeaconDetector(5, 0.1, time.Second)
	base := time.Unix(1000, 0)
	interval := 30 * time.Second

	// Build ordered timestamps then shuffle them
	ordered := makeTimestamps(6, base, interval, nil)
	shuffled := []time.Time{ordered[3], ordered[1], ordered[5], ordered[0], ordered[4], ordered[2]}
	for _, ts := range shuffled {
		d.Update("shuffled", ts)
	}

	result := d.Analyze("shuffled")
	if !result.IsBeacon {
		t.Errorf("IsBeacon: got false want true — unsorted timestamps should be sorted before analysis")
	}
	if !approxEqual(result.Interval, 30.0, 0.001) {
		t.Errorf("Interval: got %f want 30.0", result.Interval)
	}
}

// ---------------------------------------------------------------------------
// Results() returns all flows
// ---------------------------------------------------------------------------

func TestResults_MultipleFlows(t *testing.T) {
	d := NewBeaconDetector(5, 0.1, time.Second)
	base := time.Unix(0, 0)

	// beacon-flow: perfect 60s interval
	for _, ts := range makeTimestamps(8, base, 60*time.Second, nil) {
		d.Update("beacon-flow", ts)
	}
	// noisy-flow: high jitter
	jitter := []float64{1.0, -0.5, 0.8, -0.9, 1.2, 0.6, -0.7}
	for _, ts := range makeTimestamps(8, base, 60*time.Second, jitter) {
		d.Update("noisy-flow", ts)
	}

	results := d.Results()
	if len(results) != 2 {
		t.Fatalf("Results: got %d entries want 2", len(results))
	}
	if !results["beacon-flow"].IsBeacon {
		t.Error("beacon-flow: expected IsBeacon true")
	}
	if results["noisy-flow"].IsBeacon {
		t.Error("noisy-flow: expected IsBeacon false")
	}
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

func TestIatMean(t *testing.T) {
	cases := []struct {
		vals []float64
		want float64
	}{
		{nil, 0},
		{[]float64{}, 0},
		{[]float64{10}, 10},
		{[]float64{10, 20, 30}, 20},
	}
	for _, c := range cases {
		got := iatMean(c.vals)
		if !approxEqual(got, c.want, 0.0001) {
			t.Errorf("iatMean(%v): got %f want %f", c.vals, got, c.want)
		}
	}
}

func TestIatStddev(t *testing.T) {
	// Population stddev of [2,4,4,4,5,5,7,9] = 2.0
	vals := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	mean := iatMean(vals)
	got := iatStddev(vals, mean)
	if !approxEqual(got, 2.0, 0.0001) {
		t.Errorf("iatStddev: got %f want 2.0", got)
	}
}

func TestIatStddev_Uniform_IsZero(t *testing.T) {
	vals := []float64{30, 30, 30, 30, 30}
	mean := iatMean(vals)
	got := iatStddev(vals, mean)
	if got != 0 {
		t.Errorf("iatStddev(uniform): got %f want 0", got)
	}
}

func TestIatStddev_Empty(t *testing.T) {
	got := iatStddev(nil, 0)
	if got != 0 && !math.IsNaN(got) {
		t.Errorf("iatStddev(nil): got %f want 0", got)
	}
}
