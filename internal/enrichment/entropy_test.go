package enrichment

import (
	"math"
	"testing"
)

// approxEqual returns true if a and b differ by less than epsilon.
func approxEqual(a, b, epsilon float64) bool {
	return math.Abs(a-b) < epsilon
}

// ---------------------------------------------------------------------------
// Shannon — pure function
// ---------------------------------------------------------------------------

func TestShannon_Empty(t *testing.T) {
	if got := Shannon(nil); got != 0 {
		t.Errorf("Shannon(nil): got %f want 0", got)
	}
	if got := Shannon([]byte{}); got != 0 {
		t.Errorf("Shannon([]byte{}): got %f want 0", got)
	}
}

func TestShannon_SingleByte(t *testing.T) {
	// One unique byte value repeated any number of times → entropy 0
	// (no uncertainty: we always know what the next byte will be)
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0xAA
	}
	if got := Shannon(data); got != 0 {
		t.Errorf("Shannon(uniform): got %f want 0", got)
	}
}

func TestShannon_TwoEqualValues(t *testing.T) {
	// 50% 0x00, 50% 0xFF → entropy = 1.0 bit/byte
	data := make([]byte, 100)
	for i := range data {
		if i%2 == 0 {
			data[i] = 0x00
		} else {
			data[i] = 0xFF
		}
	}
	got := Shannon(data)
	if !approxEqual(got, 1.0, 0.001) {
		t.Errorf("Shannon(50/50 two values): got %f want ~1.0", got)
	}
}

func TestShannon_AllBytes_MaxEntropy(t *testing.T) {
	// All 256 byte values each appearing exactly once → entropy = 8.0 bits/byte
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	got := Shannon(data)
	if !approxEqual(got, 8.0, 0.0001) {
		t.Errorf("Shannon(all 256 bytes): got %f want 8.0", got)
	}
}

func TestShannon_Plaintext_LowEntropy(t *testing.T) {
	// ASCII English text has entropy roughly 4–5 bits/byte.
	text := []byte("The quick brown fox jumps over the lazy dog. " +
		"Pack my box with five dozen liquor jugs. " +
		"How vexingly quick daft zebras jump!")
	got := Shannon(text)
	if got < 3.5 || got > 5.5 {
		t.Errorf("Shannon(plaintext): got %f, expected in range [3.5, 5.5]", got)
	}
}

func TestShannon_HighEntropy_LooksEncrypted(t *testing.T) {
	// Pseudo-random bytes should be close to 8.0 bits/byte.
	// Use a deterministic pseudo-random sequence for reproducibility.
	data := make([]byte, 4096)
	// LCG: cheap deterministic "random-looking" bytes
	v := uint32(0xdeadbeef)
	for i := range data {
		v = v*1664525 + 1013904223
		data[i] = byte(v >> 24)
	}
	got := Shannon(data)
	if got < 7.5 {
		t.Errorf("Shannon(pseudo-random): got %f, expected >= 7.5", got)
	}
}

// ---------------------------------------------------------------------------
// IsHighEntropy
// ---------------------------------------------------------------------------

func TestIsHighEntropy(t *testing.T) {
	cases := []struct {
		score float64
		want  bool
	}{
		{0.0, false},
		{4.5, false},
		{7.1, false},
		{7.2, true}, // exactly at threshold
		{7.5, true},
		{8.0, true},
	}
	for _, c := range cases {
		got := IsHighEntropy(c.score)
		if got != c.want {
			t.Errorf("IsHighEntropy(%f): got %v want %v", c.score, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// EntropyScorer — accumulator
// ---------------------------------------------------------------------------

func TestEntropyScorer_DefaultMaxSample(t *testing.T) {
	s := NewEntropyScorer(0)
	if s.maxSample != DefaultMaxSampleBytes {
		t.Errorf("maxSample: got %d want %d", s.maxSample, DefaultMaxSampleBytes)
	}
}

func TestEntropyScorer_Update_AccumulatesPayload(t *testing.T) {
	s := NewEntropyScorer(1024)
	payload := []byte("hello world")
	s.Update("flow1", payload)
	s.Update("flow1", []byte(" more data"))

	score := s.Score("flow1")
	if score == 0 {
		t.Error("Score: got 0 after accumulating data, want > 0")
	}
}

func TestEntropyScorer_Update_EmptyFlowIDIgnored(t *testing.T) {
	s := NewEntropyScorer(1024)
	s.Update("", []byte("data"))
	scores := s.Scores()
	if len(scores) != 0 {
		t.Errorf("expected 0 scores, got %d", len(scores))
	}
}

func TestEntropyScorer_Update_EmptyPayloadIgnored(t *testing.T) {
	s := NewEntropyScorer(1024)
	s.Update("flow1", nil)
	s.Update("flow1", []byte{})
	scores := s.Scores()
	if len(scores) != 0 {
		t.Errorf("expected 0 scores after empty payloads, got %d", len(scores))
	}
}

func TestEntropyScorer_Update_CapsAtMaxSample(t *testing.T) {
	max := 10
	s := NewEntropyScorer(max)

	s.Update("flow1", make([]byte, 8))
	s.Update("flow1", make([]byte, 8)) // only 2 more bytes should be accepted

	buf := s.samples["flow1"]
	if len(buf) != max {
		t.Errorf("sample buffer: got %d bytes want %d", len(buf), max)
	}
}

func TestEntropyScorer_Update_StopsAfterCapReached(t *testing.T) {
	s := NewEntropyScorer(4)
	s.Update("flow1", []byte{0x00, 0x00, 0x00, 0x00}) // fills cap
	s.Update("flow1", []byte{0xFF, 0xFF, 0xFF, 0xFF}) // must be ignored

	// If second Update was ignored, all bytes are 0x00 → entropy 0
	if got := s.Score("flow1"); got != 0 {
		t.Errorf("Score after cap: got %f want 0 (second update should be ignored)", got)
	}
}

func TestEntropyScorer_Score_UnknownFlow(t *testing.T) {
	s := NewEntropyScorer(1024)
	if got := s.Score("nonexistent"); got != 0 {
		t.Errorf("Score(unknown): got %f want 0", got)
	}
}

func TestEntropyScorer_Scores_MultipleFlows(t *testing.T) {
	s := NewEntropyScorer(1024)

	// flow1: uniform bytes → entropy 0
	s.Update("flow1", make([]byte, 64))

	// flow2: all 256 values → entropy 8.0
	all256 := make([]byte, 256)
	for i := range all256 {
		all256[i] = byte(i)
	}
	s.Update("flow2", all256)

	scores := s.Scores()
	if len(scores) != 2 {
		t.Fatalf("Scores: got %d entries want 2", len(scores))
	}
	if scores["flow1"] != 0 {
		t.Errorf("flow1 entropy: got %f want 0", scores["flow1"])
	}
	if !approxEqual(scores["flow2"], 8.0, 0.0001) {
		t.Errorf("flow2 entropy: got %f want ~8.0", scores["flow2"])
	}
}

func TestEntropyScorer_HighEntropyFlow_DetectedCorrectly(t *testing.T) {
	s := NewEntropyScorer(4096)

	// Pseudo-random payload (same LCG as TestShannon_HighEntropy_LooksEncrypted)
	data := make([]byte, 2048)
	v := uint32(0xcafebabe)
	for i := range data {
		v = v*1664525 + 1013904223
		data[i] = byte(v >> 24)
	}

	s.Update("encrypted-flow", data)
	score := s.Score("encrypted-flow")

	if !IsHighEntropy(score) {
		t.Errorf("expected IsHighEntropy true for pseudo-random payload, got score %f", score)
	}
}
