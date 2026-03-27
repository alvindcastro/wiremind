package parser

import (
	"github.com/google/gopacket"

	"wiremind/internal/models"
)

// extractTLS pulls a TLSEvent from a TLS ClientHello, or returns nil.
// TODO Step 6d: implement TLS ClientHello parsing.
func extractTLS(_ gopacket.Packet) *models.TLSEvent {
	return nil
}
