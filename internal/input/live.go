package input

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	liveSnapLen     = 65535
	livePromiscuous = true
)

// LiveSource captures packets from a live network interface via libpcap/npcap.
// Unlike file sources, the packets channel never closes on its own —
// call Close() to stop capture.
type LiveSource struct {
	cfg     SourceConfig
	handle  *pcap.Handle
	packets chan gopacket.Packet
	meta    SourceMeta
}

func newLiveSource(cfg SourceConfig) (PacketSource, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("input: live source requires an interface name")
	}
	return &LiveSource{cfg: cfg}, nil
}

func (s *LiveSource) Open() error {
	handle, err := pcap.OpenLive(
		s.cfg.Interface,
		liveSnapLen,
		livePromiscuous,
		pcap.BlockForever,
	)
	if err != nil {
		return fmt.Errorf("input: open live %s: %w", s.cfg.Interface, err)
	}

	s.handle = handle
	s.meta = SourceMeta{
		Type:        SourceLive,
		Description: fmt.Sprintf("live interface: %s", s.cfg.Interface),
		StartedAt:   time.Now(),
	}
	s.packets = make(chan gopacket.Packet, 1000) // larger buffer for live traffic

	slog.Info("live source opened", "interface", s.cfg.Interface, "link_type", handle.LinkType())

	go s.readPackets()
	return nil
}

func (s *LiveSource) readPackets() {
	defer close(s.packets)

	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	src.NoCopy = true

	// Packets() blocks until Close() is called on the handle,
	// which causes the underlying pcap read to return an error and exit.
	for pkt := range src.Packets() {
		s.packets <- pkt
	}

	slog.Info("live source stopped", "interface", s.cfg.Interface)
}

func (s *LiveSource) Packets() <-chan gopacket.Packet { return s.packets }
func (s *LiveSource) Meta() SourceMeta                { return s.meta }

func (s *LiveSource) Close() error {
	if s.handle != nil {
		s.handle.Close() // unblocks the readPackets goroutine
		slog.Info("live source closed", "interface", s.cfg.Interface)
	}
	return nil
}
