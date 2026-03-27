package models

import (
	"net"
	"time"
)

// RawPacketMeta holds the basic metadata extracted from every packet,
// regardless of protocol. All higher-level events reference a FlowID
// derived from these fields.
type RawPacketMeta struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     net.IP    `json:"src_ip"`
	DstIP     net.IP    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"` // "TCP", "UDP", "ICMP", etc.
	Size      int       `json:"size"`     // total packet size in bytes
	FlowID    string    `json:"flow_id"`  // derived 5-tuple hash
}
