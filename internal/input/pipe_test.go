package input

import (
	"testing"
)

func TestPipeSource_DefaultsToStdin(t *testing.T) {
	src, err := newPipeSource(SourceConfig{})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	ps := src.(*PipeSource)
	if ps.cfg.FilePath != "" {
		t.Errorf("FilePath = %q, want empty (stdin mode)", ps.cfg.FilePath)
	}
}

func TestPipeSource_NonExistentFile(t *testing.T) {
	src, err := newPipeSource(SourceConfig{FilePath: "nonexistent.pipe"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	if err := src.Open(); err == nil {
		t.Error("expected error opening nonexistent pipe file, got nil")
		src.Close()
	}
}

func TestPipeSource_ReadsFromFile(t *testing.T) {
	// PipeSource can read any pcap-formatted file — reuse the fixture
	src, err := newPipeSource(SourceConfig{FilePath: fixturePath("chargen-tcp.pcap")})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	if err := src.Open(); err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer src.Close()

	if src.Meta().Type != SourcePipe {
		t.Errorf("Meta.Type = %q, want %q", src.Meta().Type, SourcePipe)
	}

	count := 0
	for range src.Packets() {
		count++
	}
	if count == 0 {
		t.Error("received 0 packets, want > 0")
	}
}
