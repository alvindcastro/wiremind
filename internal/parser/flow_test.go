package parser

import (
	"net"
	"testing"

	"wiremind/internal/models"
)

func TestFlowTracker_ChargenTCP_SingleFlow(t *testing.T) {
	result := parseFixture(t, "chargen-tcp.pcap")

	if len(result.Flows) != 1 {
		t.Fatalf("len(Flows) = %d, want 1", len(result.Flows))
	}

	f := result.Flows[0]

	if f.FlowID == "" {
		t.Error("FlowID is empty")
	}
	if f.SrcIP == nil || f.DstIP == nil {
		t.Error("SrcIP or DstIP is nil")
	}
	// canonical ID puts lower endpoint first — 176.x < 185.x
	if f.SrcIP.String() != "176.126.243.198" {
		t.Errorf("SrcIP = %s, want 176.126.243.198", f.SrcIP)
	}
	if f.DstIP.String() != "185.47.63.113" {
		t.Errorf("DstIP = %s, want 185.47.63.113", f.DstIP)
	}
}

func TestFlowTracker_ChargenTCP_State(t *testing.T) {
	result := parseFixture(t, "chargen-tcp.pcap")

	if len(result.Flows) != 1 {
		t.Fatalf("len(Flows) = %d, want 1", len(result.Flows))
	}
	if result.Flows[0].State != models.FlowStateRST {
		t.Errorf("State = %q, want RST", result.Flows[0].State)
	}
}

func TestCanonicalID_Bidirectional(t *testing.T) {
	tests := []struct {
		name    string
		srcIP   net.IP
		dstIP   net.IP
		srcPort uint16
		dstPort uint16
		proto   string
	}{
		{
			name:    "forward and reverse produce same ID",
			srcIP:   net.ParseIP("1.2.3.4"),
			dstIP:   net.ParseIP("5.6.7.8"),
			srcPort: 1234,
			dstPort: 80,
			proto:   "TCP",
		},
		{
			name:    "same port different IPs",
			srcIP:   net.ParseIP("10.0.0.1"),
			dstIP:   net.ParseIP("10.0.0.2"),
			srcPort: 443,
			dstPort: 443,
			proto:   "TCP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id1, _, _, _, _ := canonicalID(tt.srcIP, tt.dstIP, tt.srcPort, tt.dstPort, tt.proto)
			id2, _, _, _, _ := canonicalID(tt.dstIP, tt.srcIP, tt.dstPort, tt.srcPort, tt.proto)

			if id1 != id2 {
				t.Errorf("not bidirectional: A→B=%q B→A=%q", id1, id2)
			}
		})
	}
}
