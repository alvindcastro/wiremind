package models

import (
	"time"

	"gorm.io/gorm"
)

// FlowState represents the current TCP state of a flow.
type FlowState string

const (
	FlowStateSYN         FlowState = "SYN"
	FlowStateEstablished FlowState = "ESTABLISHED"
	FlowStateFIN         FlowState = "FIN"
	FlowStateRST         FlowState = "RST"
	FlowStateUnknown     FlowState = "UNKNOWN"
)

// Flow represents a reconstructed TCP or UDP conversation identified
// by its 5-tuple (src IP, dst IP, src port, dst port, protocol).
type Flow struct {
	gorm.Model  `json:"-"`
	FlowID      string    `gorm:"index;unique" json:"flow_id"`
	SrcIP       IPAddr    `gorm:"type:text" json:"src_ip"`
	DstIP       IPAddr    `gorm:"type:text" json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	StartTime   time.Time `json:"start_time"`
	LastSeen    time.Time `json:"last_seen"`
	PacketCount int       `json:"packet_count"`
	ByteCount   int64     `json:"byte_count"`
	State       FlowState `json:"state"`
}

// FlowHealth captures anomaly indicators for a flow detected during parsing.
type FlowHealth struct {
	gorm.Model      `json:"-"`
	FlowID          string `gorm:"index" json:"flow_id"`
	Retransmissions int    `json:"retransmissions"`
	RSTCount        int    `json:"rst_count"`
	ZeroWindowCount int    `json:"zero_window_count"`
	DupACKCount     int    `json:"dup_ack_count"`
	Blocked         bool   `json:"blocked"` // true if RST or persistent zero-window with no progress
}
