package input

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// PCAPNGSource reads packets from a .pcapng file.
type PCAPNGSource struct {
	cfg     SourceConfig
	handle  *pcapgo.NgReader
	file    *os.File
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
	f, err := os.Open(s.cfg.FilePath)
	if err != nil {
		return fmt.Errorf("input: open pcapng %s: %w", s.cfg.FilePath, err)
	}

	handle, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		f.Close()
		return fmt.Errorf("input: parse pcapng %s: %w", s.cfg.FilePath, err)
	}

	s.file = f
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
	if s.file != nil {
		s.file.Close()
		slog.Info("pcapng source closed", "file", s.cfg.FilePath)
	}
	return nil
}
