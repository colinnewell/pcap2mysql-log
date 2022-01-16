package decoding

import (
	"io"
	"log"
	"sync"

	"github.com/colinnewell/pcap-cli/tcp"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type MySQLConnectionReaders struct {
	mu               sync.Mutex
	builders         map[structure.ConnectionAddress]*MySQLConnectionBuilder
	IntermediateData *bool
	RawData          *bool
	verbose          *bool
	noSort           *bool
}

func New(
	intermediateData *bool,
	rawData *bool,
	verbose *bool,
	noSort *bool,
) *MySQLConnectionReaders {
	builders := make(map[structure.ConnectionAddress]*MySQLConnectionBuilder)
	return &MySQLConnectionReaders{
		builders:         builders,
		IntermediateData: intermediateData,
		RawData:          rawData,
		verbose:          verbose,
		noSort:           noSort,
	}
}

func drain(spr io.Reader, _ *tcp.TimeCaptureReader, _, _ gopacket.Flow) {
	tcpreader.DiscardBytesToEOF(spr)
}

// ReadStream tries to read tcp connections and extract MySQL connections.
func (h *MySQLConnectionReaders) ReadStream(
	r tcp.Stream, a, b gopacket.Flow,
	completed chan interface{},
) {

	t := tcp.NewTimeCaptureReader(r)
	src, dest := b.Endpoints()

	var response bool
	var address structure.ConnectionAddress
	if src.LessThan(dest) {
		address = structure.ConnectionAddress{IP: a.Reverse(), Port: b.Reverse()}
		response = true
	} else {
		address = structure.ConnectionAddress{IP: a, Port: b}
	}

	builder := h.ConnectionBuilder(address, completed)
	var buf *packet.Buffer
	if response {
		buf = builder.ResponsePacketBuffer(t)
	} else {
		buf = builder.RequestPacketBuffer(t)
	}
	defer builder.ReadDone()

	for {
		n, err := io.Copy(buf, t)
		if err != nil {
			if err == io.EOF {
				break
			}
			if *h.verbose {
				log.Printf("Error on response: %s\n", err)
			}
			drain(t, nil, a, b)
			break
		}
		if n == 0 {
			break
		}
	}
}

func (h *MySQLConnectionReaders) ConnectionBuilder(
	address structure.ConnectionAddress,
	completed chan interface{},
) *MySQLConnectionBuilder {
	h.mu.Lock()
	defer h.mu.Unlock()

	b, ok := h.builders[address]
	if !ok {
		b = NewBuilder(address, h, *h.noSort, completed)
		h.builders[address] = b
	}
	return b
}
