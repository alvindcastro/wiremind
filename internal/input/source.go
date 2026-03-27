package input

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket"
)

// SourceType identifies which input adapter is in use.
type SourceType string

const (
	SourceFile     SourceType = "file"
	SourceLive     SourceType = "live"
	SourcePipe     SourceType = "pipe"
	SourcePCAPNG   SourceType = "pcapng"
	SourceSSH      SourceType = "ssh"
	SourceAFPacket SourceType = "afpacket"
	SourceZeek     SourceType = "zeek"
	SourceS3       SourceType = "s3"
	SourceVPC      SourceType = "vpc"
	SourceKafka    SourceType = "kafka"
)

// SourceMeta carries read-only metadata about an open source.
type SourceMeta struct {
	Type        SourceType
	Description string
	StartedAt   time.Time
}

// PacketSource is the single contract all input adapters implement.
// The parser and output layers only ever speak to this interface —
// they have no knowledge of where packets actually come from.
type PacketSource interface {
	// Open initialises the source (opens file, dials network, etc.).
	Open() error

	// Packets returns a channel that emits packets until the source
	// is exhausted or closed. The channel is closed by the source
	// when no more packets will be sent.
	Packets() <-chan gopacket.Packet

	// Meta returns static metadata about this source.
	Meta() SourceMeta

	// Close releases all resources held by the source.
	Close() error
}

// SourceConfig carries all possible configuration fields for any source.
// Each adapter reads only the fields it cares about.
type SourceConfig struct {
	// file / pcapng
	FilePath string

	// live / afpacket
	Interface string

	// ssh
	SSHHost      string
	SSHUser      string
	SSHInterface string
	SSHKeyPath   string

	// s3
	S3Bucket string
	S3Key    string

	// vpc
	VPCProvider string // "aws" | "azure" | "gcp"
	VPCLogPath  string

	// kafka
	KafkaBrokers []string
	KafkaTopic   string

	// zeek
	ZeekLogDir string
}

// NewPacketSource is the factory that maps a SourceType to its adapter.
// All 10 source types are wired here; unimplemented ones return an error.
func NewPacketSource(t SourceType, cfg SourceConfig) (PacketSource, error) {
	switch t {
	case SourceFile:
		return newPCAPFileSource(cfg)
	case SourceLive:
		return nil, errors.New("input: live capture not yet implemented")
	case SourcePipe:
		return nil, errors.New("input: stdin/pipe source not yet implemented")
	case SourcePCAPNG:
		return nil, errors.New("input: pcapng source not yet implemented")
	case SourceSSH:
		return nil, errors.New("input: ssh remote capture not yet implemented")
	case SourceAFPacket:
		return nil, errors.New("input: af_packet source not yet implemented")
	case SourceZeek:
		return nil, errors.New("input: zeek log source not yet implemented")
	case SourceS3:
		return nil, errors.New("input: s3 source not yet implemented")
	case SourceVPC:
		return nil, errors.New("input: vpc flow log source not yet implemented")
	case SourceKafka:
		return nil, errors.New("input: kafka source not yet implemented")
	default:
		return nil, fmt.Errorf("input: unknown source type %q", t)
	}
}
