package parser

import (
	"testing"
)

// TODO: add tls-handshake.pcap to testdata/ to enable these tests.

func TestExtractTLS_ClientHello_SNI(t *testing.T) {
	t.Skip("requires tls-handshake.pcap fixture — pending")
}

func TestExtractTLS_ClientHello_CipherSuites(t *testing.T) {
	t.Skip("requires tls-handshake.pcap fixture — pending")
}

func TestExtractTLS_ClientHello_Version(t *testing.T) {
	t.Skip("requires tls-handshake.pcap fixture — pending")
}

func TestExtractTLS_NonTLS_ReturnsNil(t *testing.T) {
	t.Skip("requires tls-handshake.pcap fixture — pending")
}
