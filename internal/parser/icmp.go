package parser

import (
	"github.com/google/gopacket"

	"wiremind/internal/models"
)

// extractICMP pulls an ICMPEvent from an ICMPv4 or ICMPv6 packet, or returns nil.
// TODO Step 6f: implement ICMP/ICMPv6 layer extraction.
func extractICMP(_ gopacket.Packet) *models.ICMPEvent {
	return nil
}
