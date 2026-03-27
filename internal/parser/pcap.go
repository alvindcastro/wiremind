package parser

import (
	"log/slog"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"wiremind/config"
	"wiremind/internal/input"
	"wiremind/internal/models"
)

// RawStats holds packet-level counters accumulated during a parse run.
type RawStats struct {
	TotalPackets   int            `json:"total_packets"`
	TotalBytes     int64          `json:"total_bytes"`
	StartTime      time.Time      `json:"start_time"`
	EndTime        time.Time      `json:"end_time"`
	Duration       time.Duration  `json:"duration_ns"`
	ProtocolCounts map[string]int `json:"protocol_counts"`
}

// ParseResult is the output of a single parse run — one slice per event type
// plus raw stats. This is what the JSON writer consumes.
type ParseResult struct {
	Meta       input.SourceMeta    `json:"meta"`
	Stats      RawStats            `json:"stats"`
	Flows      []models.Flow       `json:"flows"`
	FlowHealth []models.FlowHealth `json:"flow_health"`
	DNS        []models.DNSEvent   `json:"dns"`
	TLS        []models.TLSEvent   `json:"tls"`
	HTTP       []models.HTTPEvent  `json:"http"`
	ICMP       []models.ICMPEvent  `json:"icmp"`
}

// Parse reads every packet from src, routes each one through the extractors,
// and returns a fully populated ParseResult.
func Parse(src input.PacketSource, cfg *config.Config) ParseResult {
	result := ParseResult{
		Meta: src.Meta(),
		Stats: RawStats{
			ProtocolCounts: make(map[string]int),
		},
	}

	ft := newFlowTracker()
	first := true

	for pkt := range src.Packets() {
		md := pkt.Metadata()

		// --- stats ---------------------------------------------------------
		if first {
			result.Stats.StartTime = md.Timestamp
			first = false
		}
		result.Stats.EndTime = md.Timestamp
		result.Stats.TotalPackets++
		result.Stats.TotalBytes += int64(md.Length)
		trackProtocol(&result.Stats, pkt)

		// --- extractors ----------------------------------------------------
		ft.update(pkt)

		if evt := extractDNS(pkt); evt != nil {
			result.DNS = append(result.DNS, *evt)
		}
		if evt := extractTLS(pkt); evt != nil {
			result.TLS = append(result.TLS, *evt)
		}
		if evt := extractHTTP(pkt); evt != nil {
			result.HTTP = append(result.HTTP, *evt)
		}
		if evt := extractICMP(pkt); evt != nil {
			result.ICMP = append(result.ICMP, *evt)
		}
	}

	result.Stats.Duration = result.Stats.EndTime.Sub(result.Stats.StartTime)
	result.Flows, result.FlowHealth = ft.results()

	slog.Info("parse complete",
		"packets", result.Stats.TotalPackets,
		"bytes", result.Stats.TotalBytes,
		"flows", len(result.Flows),
		"dns", len(result.DNS),
		"tls", len(result.TLS),
		"http", len(result.HTTP),
		"icmp", len(result.ICMP),
		"duration", result.Stats.Duration,
	)

	return result
}

// trackProtocol increments the protocol counter for a packet.
func trackProtocol(stats *RawStats, pkt gopacket.Packet) {
	if nl := pkt.NetworkLayer(); nl != nil {
		stats.ProtocolCounts[nl.LayerType().String()]++
		return
	}
	// non-IP frames (ARP, etc.)
	if ll := pkt.LinkLayer(); ll != nil {
		stats.ProtocolCounts[ll.LayerType().String()]++
		return
	}
	stats.ProtocolCounts["unknown"]++
}

// hasLayer is a small helper used by extractors to check for a layer type.
func hasLayer(pkt gopacket.Packet, t gopacket.LayerType) bool {
	return pkt.Layer(t) != nil
}

// isTCPPort returns true if the packet's TCP src or dst port matches.
func isTCPPort(pkt gopacket.Packet, port uint16) bool {
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return false
	}
	return uint16(tcp.SrcPort) == port || uint16(tcp.DstPort) == port
}
