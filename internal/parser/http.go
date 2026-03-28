package parser

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

	"wiremind/internal/models"
)

// httpPorts lists TCP destination ports treated as HTTP (not HTTPS).
var httpPorts = map[uint16]bool{
	80: true, 8080: true, 8000: true, 8008: true,
	3000: true, 4000: true, 5000: true, 9090: true,
}

// ---------------------------------------------------------------------------
// httpAssembler — stateful, fed one TCP packet at a time
// ---------------------------------------------------------------------------

// httpAssembler wraps gopacket's tcpassembly to reassemble TCP streams and
// parse HTTP request/response pairs from them.
type httpAssembler struct {
	factory   *httpStreamFactory
	assembler *tcpassembly.Assembler
	events    chan models.HTTPEvent
}

func newHTTPAssembler() *httpAssembler {
	events := make(chan models.HTTPEvent, 1000)
	factory := &httpStreamFactory{events: events}
	pool := tcpassembly.NewStreamPool(factory)
	return &httpAssembler{
		factory:   factory,
		assembler: tcpassembly.NewAssembler(pool),
		events:    events,
	}
}

// update feeds a single TCP packet into the assembler.
func (ha *httpAssembler) update(pkt gopacket.Packet) {
	nl := pkt.NetworkLayer()
	if nl == nil {
		return
	}
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return
	}
	ha.assembler.AssembleWithTimestamp(nl.NetworkFlow(), tcp, pkt.Metadata().Timestamp)
}

// flush signals end-of-capture, waits for all stream goroutines to finish,
// and returns all collected HTTP events.
func (ha *httpAssembler) flush() []models.HTTPEvent {
	ha.assembler.FlushAll()
	ha.factory.wg.Wait()
	close(ha.events)

	var result []models.HTTPEvent
	for evt := range ha.events {
		result = append(result, evt)
	}
	return result
}

// ---------------------------------------------------------------------------
// httpStreamFactory — creates one httpStream per TCP half-connection
// ---------------------------------------------------------------------------

type httpStreamFactory struct {
	events chan<- models.HTTPEvent
	wg     sync.WaitGroup
}

func (f *httpStreamFactory) New(netFlow, transport gopacket.Flow) tcpassembly.Stream {
	dstPort := uint16(binary.BigEndian.Uint16(transport.Dst().Raw()))
	s := &httpStream{
		netFlow:   netFlow,
		transport: transport,
		reader:    tcpreader.NewReaderStream(),
		events:    f.events,
		isRequest: httpPorts[dstPort],
	}
	f.wg.Add(1)
	go s.run(&f.wg)
	return &s.reader
}

// ---------------------------------------------------------------------------
// httpStream — one TCP half-connection, parsed in its own goroutine
// ---------------------------------------------------------------------------

type httpStream struct {
	netFlow   gopacket.Flow
	transport gopacket.Flow
	reader    tcpreader.ReaderStream
	events    chan<- models.HTTPEvent
	isRequest bool
}

func (s *httpStream) run(wg *sync.WaitGroup) {
	defer wg.Done()
	buf := bufio.NewReader(&s.reader)

	if s.isRequest {
		s.readRequests(buf)
	} else {
		s.readResponses(buf)
	}
}

func (s *httpStream) readRequests(buf *bufio.Reader) {
	flowID := s.flowID()
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return
		}
		if err != nil {
			tcpreader.DiscardBytesToEOF(buf)
			return
		}

		bodySize, _ := io.Copy(io.Discard, req.Body)
		req.Body.Close()

		s.events <- models.HTTPEvent{
			FlowID:    flowID,
			Direction: "request",
			Method:    req.Method,
			URL:       req.URL.String(),
			Host:      req.Host,
			UserAgent: req.UserAgent(),
			BodySize:  bodySize,
			Headers:   flattenHeaders(req.Header),
		}
	}
}

func (s *httpStream) readResponses(buf *bufio.Reader) {
	flowID := s.flowID()
	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return
		}
		if err != nil {
			tcpreader.DiscardBytesToEOF(buf)
			return
		}

		bodySize, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		s.events <- models.HTTPEvent{
			FlowID:      flowID,
			Direction:   "response",
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			BodySize:    bodySize,
			Headers:     flattenHeaders(resp.Header),
		}
	}
}

// flowID computes the canonical flow ID for this stream using the same
// canonicalID function as the flow tracker, so HTTP events link to flows.
func (s *httpStream) flowID() string {
	srcIP := net.IP(s.netFlow.Src().Raw())
	dstIP := net.IP(s.netFlow.Dst().Raw())
	srcPort := uint16(binary.BigEndian.Uint16(s.transport.Src().Raw()))
	dstPort := uint16(binary.BigEndian.Uint16(s.transport.Dst().Raw()))
	id, _, _, _, _ := canonicalID(srcIP, dstIP, srcPort, dstPort, "TCP")
	return id
}

// flattenHeaders collapses multi-value HTTP headers into a simple string map.
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = fmt.Sprintf("%s", v)
	}
	return out
}
