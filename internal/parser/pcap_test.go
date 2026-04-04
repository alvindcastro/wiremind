package parser

import (
	"path/filepath"
	"runtime"
	"testing"

	"wiremind/config"
	"wiremind/internal/input"
	"wiremind/internal/models"
)

// pcapFixturePath returns the absolute path to a file in testdata/.
func pcapFixturePath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "testdata", name)
}

// parseFixture opens a PCAP fixture file and runs Parse() against it.
func parseFixture(t *testing.T, name string) ParseResult {
	t.Helper()
	path := pcapFixturePath(name)

	src, err := input.NewPacketSource(input.SourceFile, input.SourceConfig{FilePath: path})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	if err := src.Open(); err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer src.Close()

	cfg := &config.Config{}
	return Parse(src, cfg)
}

func TestParse_ChargenTCP_Stats(t *testing.T) {
	result := parseFixture(t, "chargen-tcp.pcap")

	if result.Stats.TotalPackets != 22 {
		t.Errorf("TotalPackets = %d, want 22", result.Stats.TotalPackets)
	}
	if result.Stats.TotalBytes != 14542 {
		t.Errorf("TotalBytes = %d, want 14542", result.Stats.TotalBytes)
	}
	if result.Stats.ProtocolCounts["IPv4"] != 22 {
		t.Errorf("ProtocolCounts[IPv4] = %d, want 22", result.Stats.ProtocolCounts["IPv4"])
	}
	if result.Stats.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", result.Stats.Duration)
	}
}

func TestParse_ChargenTCP_Flows(t *testing.T) {
	result := parseFixture(t, "chargen-tcp.pcap")

	if len(result.Flows) != 1 {
		t.Fatalf("len(Flows) = %d, want 1", len(result.Flows))
	}

	f := result.Flows[0]

	if f.Protocol != "TCP" {
		t.Errorf("Protocol = %q, want TCP", f.Protocol)
	}
	if f.DstPort != 19 {
		t.Errorf("DstPort = %d, want 19 (chargen)", f.DstPort)
	}
	if f.State != models.FlowStateRST {
		t.Errorf("State = %q, want RST", f.State)
	}
	if f.PacketCount != 22 {
		t.Errorf("PacketCount = %d, want 22", f.PacketCount)
	}
	if f.ByteCount != 14542 {
		t.Errorf("ByteCount = %d, want 14542", f.ByteCount)
	}
	if f.StartTime.IsZero() || f.LastSeen.IsZero() {
		t.Error("StartTime or LastSeen is zero")
	}
}

func TestParse_ChargenTCP_NoProtocolEvents(t *testing.T) {
	// chargen-tcp.pcap has no DNS, TLS, HTTP, or ICMP traffic
	result := parseFixture(t, "chargen-tcp.pcap")

	if len(result.DNS) != 0 {
		t.Errorf("DNS events = %d, want 0", len(result.DNS))
	}
	if len(result.TLS) != 0 {
		t.Errorf("TLS events = %d, want 0", len(result.TLS))
	}
	if len(result.HTTP) != 0 {
		t.Errorf("HTTP events = %d, want 0", len(result.HTTP))
	}
	if len(result.ICMP) != 0 {
		t.Errorf("ICMP events = %d, want 0", len(result.ICMP))
	}
}
