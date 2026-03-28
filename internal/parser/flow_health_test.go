package parser

import (
	"testing"
)

func TestFlowHealth_ChargenTCP_RST(t *testing.T) {
	result := parseFixture(t, "chargen-tcp.pcap")

	if len(result.FlowHealth) != 1 {
		t.Fatalf("len(FlowHealth) = %d, want 1", len(result.FlowHealth))
	}

	h := result.FlowHealth[0]

	if h.RSTCount == 0 {
		t.Error("RSTCount = 0, want > 0")
	}
	if !h.Blocked {
		t.Error("Blocked = false, want true (RST seen)")
	}
	if h.FlowID == "" {
		t.Error("FlowID is empty")
	}
}

func TestFlowHealth_ChargenTCP_Retransmissions(t *testing.T) {
	result := parseFixture(t, "chargen-tcp.pcap")

	if len(result.FlowHealth) != 1 {
		t.Fatalf("len(FlowHealth) = %d, want 1", len(result.FlowHealth))
	}

	h := result.FlowHealth[0]

	if h.Retransmissions == 0 {
		t.Error("Retransmissions = 0, want > 0 (chargen-tcp has 2 retransmits)")
	}
}

func TestFlowHealth_FlowID_MatchesFlow(t *testing.T) {
	result := parseFixture(t, "chargen-tcp.pcap")

	if len(result.Flows) != 1 || len(result.FlowHealth) != 1 {
		t.Skip("expected 1 flow and 1 health record")
	}
	if result.Flows[0].FlowID != result.FlowHealth[0].FlowID {
		t.Errorf("FlowID mismatch: flow=%q health=%q",
			result.Flows[0].FlowID, result.FlowHealth[0].FlowID)
	}
}
