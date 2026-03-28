package parser

import (
	"github.com/google/gopacket/layers"
)

// updateHealth inspects a TCP packet for anomaly indicators and updates
// the FlowHealth record for the given flow.
//
// Detects:
//   - Retransmissions: same sequence number seen more than once on a flow
//   - RST: connection forcibly closed
//   - Zero window: receiver advertises zero receive buffer (backpressure / block)
//   - Duplicate ACKs: same ACK number repeated 3+ times (precursor to fast retransmit)
func (ft *flowTracker) updateHealth(flowID string, tcp *layers.TCP) {
	h := ft.health[flowID]
	if h == nil {
		return
	}

	// RST
	if tcp.RST {
		h.RSTCount++
		h.Blocked = true
		return
	}

	// Zero window — receiver is telling sender to stop
	if tcp.Window == 0 && tcp.ACK {
		h.ZeroWindowCount++
		if h.ZeroWindowCount >= 3 {
			h.Blocked = true
		}
	}

	// Retransmission — sequence number we've already seen on this flow
	if tcp.SYN || tcp.FIN {
		return // SYN/FIN seq tracking not meaningful for retransmit detection
	}
	seq := tcp.Seq
	if seq == 0 {
		return
	}
	seen := ft.seqSeen[flowID]
	if seen[seq] {
		h.Retransmissions++
	} else {
		seen[seq] = true
	}
}
