package parser

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"wiremind/internal/models"
)

// flowTracker accumulates per-flow state across all packets in a parse run.
// It is the only stateful component in the parser — all extractors are stateless.
type flowTracker struct {
	flows  map[string]*models.Flow
	health map[string]*models.FlowHealth
	// seqSeen tracks (flowID, seqNum) pairs for retransmission detection (used by flow_health.go)
	seqSeen map[string]map[uint32]bool
}

func newFlowTracker() *flowTracker {
	return &flowTracker{
		flows:   make(map[string]*models.Flow),
		health:  make(map[string]*models.FlowHealth),
		seqSeen: make(map[string]map[uint32]bool),
	}
}

// update folds a single packet into the flow and health maps.
func (ft *flowTracker) update(pkt gopacket.Packet) {
	nl := pkt.NetworkLayer()
	if nl == nil {
		return // non-IP frames (ARP, etc.) — skip
	}

	srcIP := net.IP(nl.NetworkFlow().Src().Raw())
	dstIP := net.IP(nl.NetworkFlow().Dst().Raw())

	var srcPort, dstPort uint16
	var proto string
	var tcpPkt *layers.TCP

	switch tl := pkt.TransportLayer().(type) {
	case *layers.TCP:
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		proto = "TCP"
		tcpPkt = tl
	case *layers.UDP:
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		proto = "UDP"
	default:
		proto = nl.LayerType().String()
	}

	flowID, cSrcIP, cDstIP, cSrcPort, cDstPort := canonicalID(srcIP, dstIP, srcPort, dstPort, proto)
	ts := pkt.Metadata().Timestamp
	size := int64(pkt.Metadata().Length)

	// --- flow ---
	flow, exists := ft.flows[flowID]
	if !exists {
		flow = &models.Flow{
			FlowID:    flowID,
			SrcIP:     cSrcIP,
			DstIP:     cDstIP,
			SrcPort:   cSrcPort,
			DstPort:   cDstPort,
			Protocol:  proto,
			StartTime: ts,
			State:     models.FlowStateUnknown,
		}
		ft.flows[flowID] = flow
		ft.health[flowID] = &models.FlowHealth{FlowID: flowID}
		ft.seqSeen[flowID] = make(map[uint32]bool)
	}

	flow.LastSeen = ts
	flow.PacketCount++
	flow.ByteCount += size

	if tcpPkt != nil {
		flow.State = nextTCPState(flow.State, tcpPkt)
		ft.updateHealth(flowID, tcpPkt)
	}
}

// results returns the finalised slices ready for ParseResult.
func (ft *flowTracker) results() ([]models.Flow, []models.FlowHealth) {
	flows := make([]models.Flow, 0, len(ft.flows))
	for _, f := range ft.flows {
		flows = append(flows, *f)
	}
	health := make([]models.FlowHealth, 0, len(ft.health))
	for _, h := range ft.health {
		health = append(health, *h)
	}
	return flows, health
}

// canonicalID produces a stable, bidirectional flow key by always placing
// the lexicographically smaller endpoint first. Returns the canonical
// src/dst so Flow.SrcIP always refers to the initiating-side endpoint.
func canonicalID(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto string) (
	id string, cSrcIP, cDstIP net.IP, cSrcPort, cDstPort uint16,
) {
	a := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)
	b := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
	if a <= b {
		return fmt.Sprintf("%s-%s-%s", a, b, proto), srcIP, dstIP, srcPort, dstPort
	}
	return fmt.Sprintf("%s-%s-%s", b, a, proto), dstIP, srcIP, dstPort, srcPort
}

// nextTCPState advances the TCP state machine for a flow given the flags in pkt.
func nextTCPState(current models.FlowState, tcp *layers.TCP) models.FlowState {
	switch {
	case tcp.RST:
		return models.FlowStateRST
	case tcp.FIN:
		return models.FlowStateFIN
	case tcp.SYN && !tcp.ACK:
		return models.FlowStateSYN
	case tcp.ACK && (current == models.FlowStateSYN || current == models.FlowStateUnknown):
		return models.FlowStateEstablished
	default:
		return current
	}
}
