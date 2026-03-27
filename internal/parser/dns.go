package parser

import (
	"github.com/google/gopacket"

	"wiremind/internal/models"
)

// extractDNS pulls a DNSEvent from a packet, or returns nil if no DNS layer is present.
// TODO Step 6c: implement DNS layer extraction.
func extractDNS(_ gopacket.Packet) *models.DNSEvent {
	return nil
}
