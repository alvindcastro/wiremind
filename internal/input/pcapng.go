package input

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PCAPNGSource reads packets from a .pcapng file.
// gopacket's pcap.OpenOffline auto-detects pcap vs pcapng, so the
// implementation mirrors PCAPFileSource with a distinct SourceType.
type PCAPNGSource struct {
	cfg     SourceConfig
	handle  *pcap.Handle
	packets chan gopacket.Packet
	meta    SourceMeta
}

func newPCAPNGSource(cfg SourceConfig) (PacketSource, error) {
	if cfg.FilePath == "" {
		return nil, fmt.Errorf("input: pcapng source requires a file path")
	}
	return &PCAPNGSource{cfg: cfg}, nil
}

func (s *PCAPNGSource) Open() error {
	handle, err := pcap.OpenOffline(s.cfg.FilePath)
	if err != nil {
		return fmt.Errorf("input: open pcapng %s: %w", s.cfg.FilePath, err)
	}

	s.handle = handle
	s.meta = SourceMeta{
		Type:        SourcePCAPNG,
		Description: fmt.Sprintf("pcapng file: %s", s.cfg.FilePath),
		StartedAt:   time.Now(),
	}
	s.packets = make(chan gopacket.Packet, 100)

	slog.Info("pcapng source opened", "file", s.cfg.FilePath, "link_type", handle.LinkType())

	go s.readPackets()
	return nil
}

func (s *PCAPNGSource) readPackets() {
	defer close(s.packets)

	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	src.NoCopy = true

	for pkt := range src.Packets() {
		s.packets <- pkt
	}

	slog.Info("pcapng source exhausted", "file", s.cfg.FilePath)
}

func (s *PCAPNGSource) Packets() <-chan gopacket.Packet { return s.packets }
func (s *PCAPNGSource) Meta() SourceMeta                { return s.meta }

func (s *PCAPNGSource) Close() error {
	if s.handle != nil {
		s.handle.Close()
		slog.Info("pcapng source closed", "file", s.cfg.FilePath)
	}
	return nil
}
