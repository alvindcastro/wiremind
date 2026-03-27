package models

import (
	"net"
	"time"
)

// DNSQuestion holds a single question entry from a DNS message.
type DNSQuestion struct {
	Name string `json:"name"`
	Type string `json:"type"` // "A", "AAAA", "CNAME", "MX", etc.
}

// DNSAnswer holds a single resource record from a DNS response.
type DNSAnswer struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"` // resolved value (IP, CNAME target, etc.)
}

// DNSEvent represents a single DNS query or response.
type DNSEvent struct {
	FlowID     string        `json:"flow_id"`
	Timestamp  time.Time     `json:"timestamp"`
	QueryID    uint16        `json:"query_id"`
	IsResponse bool          `json:"is_response"`
	Opcode     uint8         `json:"opcode"`
	RCode      string        `json:"rcode"` // "NOERROR", "NXDOMAIN", etc.
	Questions  []DNSQuestion `json:"questions"`
	Answers    []DNSAnswer   `json:"answers"`
}

// TLSEvent represents a TLS ClientHello handshake extracted from a TCP stream.
type TLSEvent struct {
	FlowID            string    `json:"flow_id"`
	Timestamp         time.Time `json:"timestamp"`
	Version           string    `json:"version"`            // negotiated TLS version
	SNI               string    `json:"sni"`                // server name from ClientHello
	CipherSuites      []string  `json:"cipher_suites"`      // offered cipher suite names
	SupportedVersions []string  `json:"supported_versions"` // from supported_versions extension
	IsClientHello     bool      `json:"is_client_hello"`
}

// HTTPEvent represents a single HTTP request or response reassembled from a TCP stream.
type HTTPEvent struct {
	FlowID      string            `json:"flow_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Direction   string            `json:"direction"`    // "request" or "response"
	Method      string            `json:"method"`       // GET, POST, etc. (request only)
	URL         string            `json:"url"`          // request only
	Host        string            `json:"host"`         // Host header
	UserAgent   string            `json:"user_agent"`   // request only
	StatusCode  int               `json:"status_code"`  // response only
	ContentType string            `json:"content_type"` // response only
	BodySize    int64             `json:"body_size"`    // bytes
	Headers     map[string]string `json:"headers"`
}

// ICMPEvent represents a single ICMP or ICMPv6 packet.
type ICMPEvent struct {
	FlowID    string    `json:"flow_id"`
	Timestamp time.Time `json:"timestamp"`
	SrcIP     net.IP    `json:"src_ip"`
	DstIP     net.IP    `json:"dst_ip"`
	TypeCode  uint8     `json:"type_code"`
	Code      uint8     `json:"code"`
	TypeName  string    `json:"type_name"` // human-readable: "EchoRequest", "DestUnreachable", etc.
	Size      int       `json:"size"`
}
