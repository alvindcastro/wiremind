package input

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// PipeSource reads a pcap stream from stdin or a named pipe.
// Typical usage: tcpdump -i eth0 -w - | forensics parse --input pipe
//
// If SourceConfig.FilePath is empty, reads from os.Stdin.
// If FilePath is set, opens that path as a named pipe or regular file.
type PipeSource struct {
	cfg     SourceConfig
	handle  *pcapgo.Reader
	file    *os.File
	packets chan gopacket.Packet
	meta    SourceMeta
}

func newPipeSource(cfg SourceConfig) (PacketSource, error) {
	return &PipeSource{cfg: cfg}, nil
}

func (s *PipeSource) Open() error {
	var (
		f    *os.File
		desc string
	)

	if s.cfg.FilePath == "" {
		f = os.Stdin
		desc = "stdin"
	} else {
		var err error
		f, err = os.Open(s.cfg.FilePath)
		if err != nil {
			return fmt.Errorf("input: open pipe %s: %w", s.cfg.FilePath, err)
		}
		desc = fmt.Sprintf("pipe: %s", s.cfg.FilePath)
	}

	handle, err := pcapgo.NewReader(f)
	if err != nil {
		return fmt.Errorf("input: parse pcap from %s: %w", desc, err)
	}

	s.file = f
	s.handle = handle
	s.meta = SourceMeta{
		Type:        SourcePipe,
		Description: desc,
		StartedAt:   time.Now(),
	}
	s.packets = make(chan gopacket.Packet, 100)

	slog.Info("pipe source opened", "source", desc, "link_type", handle.LinkType())

	go s.readPackets()
	return nil
}

func (s *PipeSource) readPackets() {
	defer close(s.packets)

	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	src.NoCopy = true

	for pkt := range src.Packets() {
		s.packets <- pkt
	}

	slog.Info("pipe source exhausted", "source", s.meta.Description)
}

func (s *PipeSource) Packets() <-chan gopacket.Packet { return s.packets }
func (s *PipeSource) Meta() SourceMeta                { return s.meta }

func (s *PipeSource) Close() error {
	if s.file != nil && s.file != os.Stdin {
		s.file.Close()
	}
	slog.Info("pipe source closed", "source", s.meta.Description)
	return nil
}
