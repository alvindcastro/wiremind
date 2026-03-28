package parser

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"wiremind/internal/models"
)

// extractDNS pulls a DNSEvent from a packet, or returns nil if no DNS layer is present.
func extractDNS(pkt gopacket.Packet) *models.DNSEvent {
	layer := pkt.Layer(layers.LayerTypeDNS)
	if layer == nil {
		return nil
	}
	dns, ok := layer.(*layers.DNS)
	if !ok {
		return nil
	}

	evt := &models.DNSEvent{
		FlowID:     flowIDFromPacket(pkt),
		Timestamp:  pkt.Metadata().Timestamp,
		QueryID:    dns.ID,
		IsResponse: dns.QR,
		Opcode:     uint8(dns.OpCode),
		RCode:      dns.ResponseCode.String(),
	}

	for _, q := range dns.Questions {
		evt.Questions = append(evt.Questions, models.DNSQuestion{
			Name: string(q.Name),
			Type: q.Type.String(),
		})
	}

	for _, a := range dns.Answers {
		evt.Answers = append(evt.Answers, models.DNSAnswer{
			Name: string(a.Name),
			Type: a.Type.String(),
			TTL:  a.TTL,
			Data: dnsRecordData(a),
		})
	}

	return evt
}

// dnsRecordData formats the data field of a DNS resource record into a
// human-readable string based on the record type.
func dnsRecordData(rr layers.DNSResourceRecord) string {
	switch rr.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		if rr.IP != nil {
			return rr.IP.String()
		}
	case layers.DNSTypeCNAME:
		return string(rr.CNAME)
	case layers.DNSTypePTR:
		return string(rr.PTR)
	case layers.DNSTypeNS:
		return string(rr.NS)
	case layers.DNSTypeMX:
		return fmt.Sprintf("%d %s", rr.MX.Preference, string(rr.MX.Name))
	case layers.DNSTypeTXT:
		parts := make([]string, 0, len(rr.TXTs))
		for _, t := range rr.TXTs {
			parts = append(parts, string(t))
		}
		return strings.Join(parts, " ")
	case layers.DNSTypeSOA:
		return fmt.Sprintf("%s %s serial=%d", string(rr.SOA.MName), string(rr.SOA.RName), rr.SOA.Serial)
	}
	return fmt.Sprintf("(raw %d bytes)", len(rr.Data))
}
