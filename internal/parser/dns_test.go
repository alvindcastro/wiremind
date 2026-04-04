package parser

import (
	"testing"
)

// TODO: add dns-capture.pcap to testdata/ to enable these tests.

func TestExtractDNS_Query(t *testing.T) {
	t.Skip("requires dns-capture.pcap fixture — pending")
}

func TestExtractDNS_Response(t *testing.T) {
	t.Skip("requires dns-capture.pcap fixture — pending")
}

func TestExtractDNS_NXDOMAIN(t *testing.T) {
	t.Skip("requires dns-capture.pcap fixture — pending")
}
