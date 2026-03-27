package parser

import (
	"github.com/google/gopacket"

	"wiremind/internal/models"
)

// flowTracker accumulates per-flow state across all packets in a parse run.
// Implemented in Step 6a.
type flowTracker struct {
	flows  map[string]*models.Flow
	health map[string]*models.FlowHealth
}

func newFlowTracker() *flowTracker {
	return &flowTracker{
		flows:  make(map[string]*models.Flow),
		health: make(map[string]*models.FlowHealth),
	}
}

// update processes a single packet into the flow map.
// TODO Step 6a: implement 5-tuple tracking, state machine, byte/packet counts.
func (ft *flowTracker) update(_ gopacket.Packet) {}

// results returns the finalised slices for ParseResult.
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
