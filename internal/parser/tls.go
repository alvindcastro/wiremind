package parser

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"wiremind/internal/models"
)

// extractTLS parses a TLS ClientHello from a TCP payload and returns a TLSEvent,
// or nil if the packet is not a TLS ClientHello.
//
// gopacket's TLS layer does not decode ClientHello internals (SNI, cipher suites,
// extensions), so we parse the raw TCP payload directly.
func extractTLS(pkt gopacket.Packet) *models.TLSEvent {
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || len(tcp.Payload) < 9 {
		return nil
	}

	p := tcp.Payload

	// TLS record header: ContentType(1) + Version(2) + Length(2)
	// ContentType 0x16 = Handshake
	if p[0] != 0x16 || p[1] != 0x03 {
		return nil
	}

	// Handshake header at byte 5: HandshakeType(1) + Length(3)
	// HandshakeType 0x01 = ClientHello
	if p[5] != 0x01 {
		return nil
	}

	evt := &models.TLSEvent{
		FlowID:        flowIDFromPacket(pkt),
		Timestamp:     pkt.Metadata().Timestamp,
		IsClientHello: true,
	}

	// ClientHello body starts at byte 9
	body := p[9:]
	if len(body) < 35 {
		return evt // too short to contain version + random
	}

	// Client legacy version (2 bytes) — real version is in supported_versions extension
	evt.Version = tlsVersionName(binary.BigEndian.Uint16(body[0:2]))

	// Skip: Random(32) → offset 2+32 = 34
	offset := 34

	// Session ID
	if offset >= len(body) {
		return evt
	}
	sessionIDLen := int(body[offset])
	offset += 1 + sessionIDLen

	// Cipher suites
	if offset+2 > len(body) {
		return evt
	}
	csLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+csLen > len(body) {
		return evt
	}
	for i := 0; i+1 < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(body[offset+i : offset+i+2])
		evt.CipherSuites = append(evt.CipherSuites, tlsCipherSuiteName(cs))
	}
	offset += csLen

	// Compression methods
	if offset >= len(body) {
		return evt
	}
	compLen := int(body[offset])
	offset += 1 + compLen

	// Extensions
	if offset+2 > len(body) {
		return evt
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotalLen

	for offset+4 <= extEnd && offset+4 <= len(body) {
		extType := binary.BigEndian.Uint16(body[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > len(body) {
			break
		}
		extData := body[offset : offset+extLen]

		switch extType {
		case 0x0000: // server_name
			evt.SNI = parseSNI(extData)
		case 0x002b: // supported_versions
			evt.SupportedVersions = parseSupportedVersions(extData)
			// prefer the negotiated version from this extension
			if len(evt.SupportedVersions) > 0 {
				evt.Version = evt.SupportedVersions[0]
			}
		}

		offset += extLen
	}

	return evt
}

// parseSNI extracts the server name from the SNI extension data.
//
// SNI extension layout:
//
//	ServerNameList length (2) → ServerNameType (1) → NameLength (2) → Name
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// skip ServerNameList length (2 bytes)
	nameType := data[2]
	if nameType != 0x00 { // 0x00 = host_name
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// parseSupportedVersions extracts the list of TLS versions from the
// supported_versions extension (type 0x002b).
func parseSupportedVersions(data []byte) []string {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	var versions []string
	for i := 1; i+1 < 1+listLen && i+1 <= len(data); i += 2 {
		v := binary.BigEndian.Uint16(data[i : i+2])
		versions = append(versions, tlsVersionName(v))
	}
	return versions
}

// tlsVersionName maps a TLS version uint16 to its human-readable name.
func tlsVersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// tlsCipherSuiteName maps a cipher suite uint16 to its IANA name.
// Falls back to hex for unknown suites.
func tlsCipherSuiteName(cs uint16) string {
	names := map[uint16]string{
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
		0x0a0a: "GREASE",
	}
	if name, ok := names[cs]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", cs)
}
