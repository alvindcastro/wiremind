package parser

import (
	"testing"
)

// TODO: add icmp-ping.pcap to scripts/sample_pcaps/ to enable these tests.

func TestExtractICMP_EchoRequest(t *testing.T) {
	t.Skip("requires icmp-ping.pcap fixture — pending")
}

func TestExtractICMP_EchoReply(t *testing.T) {
	t.Skip("requires icmp-ping.pcap fixture — pending")
}

func TestExtractICMP_Unreachable(t *testing.T) {
	t.Skip("requires icmp-ping.pcap fixture — pending")
}
