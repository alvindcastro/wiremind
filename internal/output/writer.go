package output

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"wiremind/internal/parser"
)

// WriteJSON writes every field of a ParseResult to its own JSON file under dir.
// The directory is created if it does not exist.
//
// Output files:
//
//	meta.json         — source metadata + run timestamp
//	raw_stats.json    — packet counters, protocol breakdown, capture duration
//	flows.json        — reconstructed TCP/UDP flows
//	flow_health.json  — per-flow anomaly indicators
//	dns.json          — DNS query/response events
//	tls.json          — TLS ClientHello events (SNI, cipher suites)
//	http.json         — reassembled HTTP request/response pairs
//	icmp.json         — ICMP/ICMPv6 events
func WriteJSON(result parser.ParseResult, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("output: create dir %s: %w", dir, err)
	}

	files := []struct {
		name string
		data any
	}{
		{"meta.json", newMetaEnvelope(result)},
		{"raw_stats.json", result.Stats},
		{"flows.json", result.Flows},
		{"flow_health.json", result.FlowHealth},
		{"dns.json", result.DNS},
		{"tls.json", result.TLS},
		{"http.json", result.HTTP},
		{"icmp.json", result.ICMP},
	}

	for _, f := range files {
		if err := writeFile(filepath.Join(dir, f.name), f.data); err != nil {
			return err
		}
	}

	slog.Info("output written", "dir", dir, "files", len(files))
	return nil
}

// writeFile marshals v to indented JSON and writes it to path.
func writeFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("output: marshal %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("output: write %s: %w", path, err)
	}
	slog.Debug("wrote output file", "path", path, "bytes", len(b))
	return nil
}

// runMeta wraps SourceMeta with a run timestamp for audit purposes.
type runMeta struct {
	Source    any       `json:"source"`
	WrittenAt time.Time `json:"written_at"`
}

func newMetaEnvelope(result parser.ParseResult) runMeta {
	return runMeta{
		Source:    result.Meta,
		WrittenAt: time.Now().UTC(),
	}
}
