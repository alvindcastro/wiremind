package input

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// PCAPFileSource reads packets from a .pcap file and emits them on a channel.
// It implements PacketSource and is the primary source used during Phase 1.
type PCAPFileSource struct {
	cfg     SourceConfig
	handle  *pcapgo.Reader
	file    *os.File
	packets chan gopacket.Packet
	meta    SourceMeta
}

func newPCAPFileSource(cfg SourceConfig) (PacketSource, error) {
	if cfg.FilePath == "" {
		return nil, fmt.Errorf("input: pcap file source requires a file path")
	}
	return &PCAPFileSource{cfg: cfg}, nil
}

// Open opens the .pcap file and starts emitting packets in a background goroutine.
// The packets channel is closed automatically when the file is exhausted.
func (s *PCAPFileSource) Open() error {
	f, err := os.Open(s.cfg.FilePath)
	if err != nil {
		return fmt.Errorf("input: open pcap %s: %w", s.cfg.FilePath, err)
	}

	handle, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return fmt.Errorf("input: parse pcap %s: %w", s.cfg.FilePath, err)
	}

	s.file = f
	s.handle = handle
	s.meta = SourceMeta{
		Type:        SourceFile,
		Description: fmt.Sprintf("pcap file: %s", s.cfg.FilePath),
		StartedAt:   time.Now(),
	}
	s.packets = make(chan gopacket.Packet, 100)

	slog.Info("pcap file source opened", "file", s.cfg.FilePath, "link_type", handle.LinkType())

	go s.readPackets()
	return nil
}

func (s *PCAPFileSource) readPackets() {
	defer close(s.packets)

	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	src.NoCopy = true

	for pkt := range src.Packets() {
		s.packets <- pkt
	}

	slog.Info("pcap file source exhausted", "file", s.cfg.FilePath)
}

func (s *PCAPFileSource) Packets() <-chan gopacket.Packet {
	return s.packets
}

func (s *PCAPFileSource) Meta() SourceMeta {
	return s.meta
}

func (s *PCAPFileSource) Close() error {
	if s.file != nil {
		s.file.Close()
		slog.Info("pcap file source closed", "file", s.cfg.FilePath)
	}
	return nil
}
