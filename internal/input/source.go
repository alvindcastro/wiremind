package input

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
)

// SourceType identifies which input adapter is in use.
type SourceType string

const (
	SourceFile   SourceType = "file"
	SourcePCAPNG SourceType = "pcapng"
	SourceLive   SourceType = "live"
	SourcePipe   SourceType = "pipe"
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

// SourceConfig carries configuration fields for all supported sources.
// Each adapter reads only the fields it cares about.
type SourceConfig struct {
	// file / pcapng
	FilePath string

	// live
	Interface string
}

// NewPacketSource maps a SourceType to its adapter implementation.
func NewPacketSource(t SourceType, cfg SourceConfig) (PacketSource, error) {
	switch t {
	case SourceFile:
		return newPCAPFileSource(cfg)
	case SourcePCAPNG:
		return newPCAPNGSource(cfg)
	case SourceLive:
		return newLiveSource(cfg)
	case SourcePipe:
		return newPipeSource(cfg)
	default:
		return nil, fmt.Errorf("input: unknown source type %q", t)
	}
}
