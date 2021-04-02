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
	Transmission(typeName string, t interface{})
	ConnectionBuilder() ConnectionBuilder
}

type TransmissionEmitter struct {
	Request bool
	Times   TimesSeen
	Builder *MySQLConnectionBuilder
}

func (e *TransmissionEmitter) Transmission(typeName string, t interface{}) {
	e.Builder.AddToConnection(e.Request, e.Times.Seen(), typeName, t)
	e.Times.Reset()
}

func (e *TransmissionEmitter) ConnectionBuilder() ConnectionBuilder {
	return e.Builder
}

type RawDataEmitter struct {
	read    bytes.Buffer
	emitter Emitter
}

func SetupRawDataEmitter(e Emitter, rdr io.Reader) (io.Reader, *RawDataEmitter) {
	emitter := RawDataEmitter{emitter: e}
	return io.TeeReader(rdr, &emitter.read), &emitter
}

func (e *RawDataEmitter) Transmission(typeName string, t interface{}) {
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
	e.emitter.Transmission(typeName, structure.WithRawPacket{RawData: data, Transmission: t})
	e.read.Reset()
}

func (e *RawDataEmitter) ConnectionBuilder() ConnectionBuilder {
	return e.emitter.ConnectionBuilder()
}