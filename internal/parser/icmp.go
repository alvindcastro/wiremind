package parser

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"wiremind/internal/models"
)

// extractICMP pulls an ICMPEvent from an ICMPv4 or ICMPv6 packet, or returns nil.
func extractICMP(pkt gopacket.Packet) *models.ICMPEvent {
	if v4 := pkt.Layer(layers.LayerTypeICMPv4); v4 != nil {
		return icmpv4Event(pkt, v4.(*layers.ICMPv4))
	}
	if v6 := pkt.Layer(layers.LayerTypeICMPv6); v6 != nil {
		return icmpv6Event(pkt, v6.(*layers.ICMPv6))
	}
	return nil
}

func icmpv4Event(pkt gopacket.Packet, icmp *layers.ICMPv4) *models.ICMPEvent {
	srcIP, dstIP := ipsFromPacket(pkt)
	t := icmp.TypeCode.Type()
	c := icmp.TypeCode.Code()
	return &models.ICMPEvent{
		FlowID:    flowIDFromPacket(pkt),
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		TypeCode:  t,
		Code:      c,
		TypeName:  icmpv4TypeName(t, c),
		Size:      pkt.Metadata().Length,
	}
}

func icmpv6Event(pkt gopacket.Packet, icmp *layers.ICMPv6) *models.ICMPEvent {
	srcIP, dstIP := ipsFromPacket(pkt)
	t := icmp.TypeCode.Type()
	c := icmp.TypeCode.Code()
	return &models.ICMPEvent{
		FlowID:    flowIDFromPacket(pkt),
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		TypeCode:  t,
		Code:      c,
		TypeName:  icmpv6TypeName(t, c),
		Size:      pkt.Metadata().Length,
	}
}

// ipsFromPacket extracts src/dst IPs from the network layer.
func ipsFromPacket(pkt gopacket.Packet) (src, dst net.IP) {
	if nl := pkt.NetworkLayer(); nl != nil {
		src = net.IP(nl.NetworkFlow().Src().Raw())
		dst = net.IP(nl.NetworkFlow().Dst().Raw())
	}
	return
}

// icmpv4TypeName returns a human-readable name for an ICMPv4 type/code pair.
func icmpv4TypeName(t, c uint8) string {
	switch t {
	case 0:
		return "EchoReply"
	case 3:
		codes := map[uint8]string{
			0: "NetUnreachable", 1: "HostUnreachable", 2: "ProtoUnreachable",
			3: "PortUnreachable", 4: "FragNeeded", 5: "SrcRouteFailed",
		}
		if name, ok := codes[c]; ok {
			return "DestUnreachable/" + name
		}
		return "DestUnreachable"
	case 4:
		return "SourceQuench"
	case 5:
		return "Redirect"
	case 8:
		return "EchoRequest"
	case 9:
		return "RouterAdvertisement"
	case 10:
		return "RouterSolicitation"
	case 11:
		if c == 0 {
			return "TimeExceeded/TTLExceeded"
		}
		return "TimeExceeded/FragReassembly"
	case 12:
		return "ParameterProblem"
	case 13:
		return "TimestampRequest"
	case 14:
		return "TimestampReply"
	case 30:
		return "Traceroute"
	default:
		return icmpUnknown(t, c)
	}
}

// icmpv6TypeName returns a human-readable name for an ICMPv6 type/code pair.
func icmpv6TypeName(t, c uint8) string {
	switch t {
	case 1:
		return "DestUnreachable"
	case 2:
		return "PacketTooBig"
	case 3:
		if c == 0 {
			return "TimeExceeded/HopLimit"
		}
		return "TimeExceeded/FragReassembly"
	case 4:
		return "ParameterProblem"
	case 128:
		return "EchoRequest"
	case 129:
		return "EchoReply"
	case 133:
		return "RouterSolicitation"
	case 134:
		return "RouterAdvertisement"
	case 135:
		return "NeighborSolicitation"
	case 136:
		return "NeighborAdvertisement"
	case 137:
		return "Redirect"
	default:
		return icmpUnknown(t, c)
	}
}

func icmpUnknown(t, c uint8) string {
	return "Unknown(" + uint8Str(t) + "/" + uint8Str(c) + ")"
}

func uint8Str(n uint8) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 3)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
