package enrichment

import "math"

const (
	// DefaultMaxSampleBytes is the maximum payload bytes accumulated per flow
	// before sampling stops. 4 KB gives a statistically representative entropy
	// estimate without unbounded memory growth on large flows.
	DefaultMaxSampleBytes = 4096

	// HighEntropyThreshold is the Shannon entropy (bits/byte) above which a
	// payload is considered likely encrypted or packed.
	// Reference points:
	//   English plaintext   ≈ 4.5 bits/byte
	//   Compressed data     ≈ 6–7 bits/byte
	//   AES ciphertext      ≈ 7.9 bits/byte
	//   Uniform random      = 8.0 bits/byte (theoretical max)
	HighEntropyThreshold = 7.2
)

// Shannon computes the Shannon entropy of data in bits per byte.
// Returns 0.0 for empty or single-value input. Maximum is 8.0 (all 256 byte
// values equally likely).
func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	n := float64(len(data))
	var h float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// IsHighEntropy reports whether score meets or exceeds HighEntropyThreshold.
func IsHighEntropy(score float64) bool {
	return score >= HighEntropyThreshold
}

// EntropyScorer accumulates payload bytes per flow and computes per-flow
// Shannon entropy on demand. Feed bytes with Update; retrieve scores with
// Score or Scores.
//
// The scorer is intentionally decoupled from gopacket — the caller extracts
// the payload bytes and the flow ID, then calls Update. This keeps the
// enrichment package independent of the parsing layer.
type EntropyScorer struct {
	samples   map[string][]byte // flowID → accumulated payload bytes
	maxSample int               // byte cap per flow
}

// NewEntropyScorer creates a scorer. maxSampleBytes caps how many payload
// bytes are collected per flow; pass 0 to use DefaultMaxSampleBytes.
func NewEntropyScorer(maxSampleBytes int) *EntropyScorer {
	if maxSampleBytes <= 0 {
		maxSampleBytes = DefaultMaxSampleBytes
	}
	return &EntropyScorer{
		samples:   make(map[string][]byte),
		maxSample: maxSampleBytes,
	}
}

// Update appends payload bytes to the sample buffer for flowID.
// Once the buffer reaches maxSampleBytes the call is a no-op.
// Empty flowID or empty payload are silently ignored.
func (s *EntropyScorer) Update(flowID string, payload []byte) {
	if flowID == "" || len(payload) == 0 {
		return
	}

	sample := s.samples[flowID]
	remaining := s.maxSample - len(sample)
	if remaining <= 0 {
		return
	}
	if len(payload) > remaining {
		payload = payload[:remaining]
	}
	s.samples[flowID] = append(sample, payload...)
}

// Score returns the Shannon entropy for flowID's accumulated payload.
// Returns 0 if no bytes were collected for this flow.
func (s *EntropyScorer) Score(flowID string) float64 {
	return Shannon(s.samples[flowID])
}

// Scores returns a map of flowID → Shannon entropy for every flow that had
// at least one payload byte collected.
func (s *EntropyScorer) Scores() map[string]float64 {
	out := make(map[string]float64, len(s.samples))
	for id, data := range s.samples {
		out[id] = Shannon(data)
	}
	return out
}
