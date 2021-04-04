package decoding

import (
	"io"
	"log"
	"sort"
	"sync"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/colinnewell/pcap2mysql-log/pkg/tcp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type MySQLConnectionReaders struct {
	mu       sync.Mutex
	builders map[structure.ConnectionAddress]*MySQLConnectionBuilder
	rawData  bool
	verbose  bool
}

func New(rawData bool, verbose bool) *MySQLConnectionReaders {
	builders := make(map[structure.ConnectionAddress]*MySQLConnectionBuilder)
	return &MySQLConnectionReaders{
		builders: builders,
		rawData:  rawData,
		verbose:  verbose,
	}
}

func (h *MySQLConnectionReaders) GetConnections() []structure.Connection {
	connections := make([]structure.Connection, len(h.builders))
	i := 0
	for _, b := range h.builders {
		connections[i] = b.Connection()
		i++
	}
	sort.Slice(connections, func(i, j int) bool {
		if connections[i].FirstSeen().Before(connections[j].FirstSeen()) {
			return true
		} else if connections[j].FirstSeen().Before(connections[i].FirstSeen()) {
			return false
		} else {
			return connections[i].Address.String() > connections[j].Address.String()
		}
	})
	return connections
}

type streamDecoder func(io.Reader, *tcp.TimeCaptureReader, gopacket.Flow, gopacket.Flow) error

func drain(spr io.Reader, _ *tcp.TimeCaptureReader, _, _ gopacket.Flow) error {
	tcpreader.DiscardBytesToEOF(spr)
	return nil
}

// ReadStream tries to read tcp connections and extract MySQL connections.
func (h *MySQLConnectionReaders) ReadStream(r tcp.Stream, a, b gopacket.Flow) {
	t := tcp.NewTimeCaptureReader(r)
	spr := tcp.NewSavePointReader(t)
	src, dest := b.Endpoints()
	decoders := [2]streamDecoder{}
	if src.LessThan(dest) {
		// assume response
		decoders[0] = h.ReadMySQLResponse
	} else {
		// assume request
		decoders[0] = h.ReadRequestDecoder
	}
	decoders[1] = drain

	for {
		for i, decode := range decoders {
			spr.SavePoint()
			err := decode(spr, t, a, b)
			if err == nil {
				break
			}
			if err == io.EOF {
				return
			} else if err != nil {
				// don't need to restore before the last one
				if i+1 < len(decoders) {
					// can discard the save point on the final restore
					spr.Restore(i < len(decoders))
				}
			}
		}
		t.Reset()
	}
}

// ReadMySQLResponse try to read the stream as an MySQL response.
func (h *MySQLConnectionReaders) ReadMySQLResponse(
	spr io.Reader, t *tcp.TimeCaptureReader, a, b gopacket.Flow,
) error {
	address := structure.ConnectionAddress{IP: a.Reverse(), Port: b.Reverse()}
	var e Emitter
	e = &TransmissionEmitter{
		Request: false,
		Times:   t,
		Builder: h.ConnectionBuilder(address),
	}
	if h.rawData {
		spr, e = SetupRawDataEmitter(e, spr)
	}
	interpreter := ResponseDecoder{Emit: e}

	if _, err := packet.Copy(spr, &interpreter); err != nil {
		if h.verbose {
			log.Printf("Error on response: %s\n", err)
		}
		return err
	}
	interpreter.FlushResponse()

	return nil
}

// ReadRequestDecoder try to read the stream as an MySQL request.
func (h *MySQLConnectionReaders) ReadRequestDecoder(
	spr io.Reader, t *tcp.TimeCaptureReader, a, b gopacket.Flow,
) error {
	address := structure.ConnectionAddress{IP: a, Port: b}
	var e Emitter
	e = &TransmissionEmitter{
		Request: true,
		Times:   t,
		Builder: h.ConnectionBuilder(address),
	}
	if h.rawData {
		spr, e = SetupRawDataEmitter(e, spr)
	}
	interpreter := RequestDecoder{
		Emit: e,
	}

	if _, err := packet.Copy(spr, &interpreter); err != nil {
		if h.verbose {
			log.Printf("Error on request: %s\n", err)
		}
		return err
	}

	return nil
}

func (h *MySQLConnectionReaders) ConnectionBuilder(
	address structure.ConnectionAddress,
) *MySQLConnectionBuilder {
	h.mu.Lock()
	defer h.mu.Unlock()

	b, ok := h.builders[address]
	if !ok {
		b = NewBuilder(address, h)
		h.builders[address] = b
	}
	return b
}
