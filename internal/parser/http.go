package parser

import (
	"github.com/google/gopacket"

	"wiremind/internal/models"
)

// extractHTTP reassembles TCP streams and extracts HTTP request/response pairs.
// Returns nil for non-HTTP packets or incomplete streams.
// TODO Step 6e: implement TCP stream reassembly via gopacket/tcpassembly.
func extractHTTP(_ gopacket.Packet) *models.HTTPEvent {
	return nil
}
