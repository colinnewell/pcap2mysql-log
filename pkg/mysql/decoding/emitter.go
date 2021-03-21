package decoding

import (
	"bytes"
	"io"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
)

type TimesSeen interface {
	Reset()
	Seen() []time.Time
}

type Emitter interface {
	Transmission(t interface{})
}

type TransmissionEmitter struct {
	Request bool
	Times   TimesSeen
	Builder *MySQLConnectionBuilder
}

func (e *TransmissionEmitter) Transmission(t interface{}) {
	e.Builder.AddToConnection(e.Request, e.Times.Seen(), t)
	e.Times.Reset()
}

type RawDataEmitter struct {
	read    bytes.Buffer
	emitter Emitter
}

func SetupRawDataEmitter(e Emitter, rdr io.Reader) (io.Reader, *RawDataEmitter) {
	emitter := RawDataEmitter{emitter: e}
	return io.TeeReader(rdr, &emitter.read), &emitter
}

func (e *RawDataEmitter) Transmission(t interface{}) {
	// take the buffer that has been emitted and tag that onto what we're
	// emitting
	// this feels flawed, should I be copying the byte array?
	data := make([]byte, e.read.Len())
	if e.read.Len() > 0 {
		if _, err := e.read.Read(data); err != nil {
			// shouldn't really be possible to have an error here.
			panic(err)
		}
	}
	e.emitter.Transmission(structure.WithRawPacket{RawData: data, Transmission: t})
	e.read.Reset()
}
