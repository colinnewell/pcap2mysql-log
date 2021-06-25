package decoding

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
)

const bothSides = 2

type ConnectionBuilder interface {
	AddToConnection(
		request bool, seen []time.Time, typeName string, item interface{},
	)
	JustSeenGreeting() bool
	PreviousRequestType() string
	ParamsForQuery(query uint32) uint16
}

type MySQLConnectionBuilder struct {
	Address             structure.ConnectionAddress
	Readers             *MySQLConnectionReaders
	Requests            []structure.Transmission
	Responses           []structure.Transmission
	previousRequestType string
	justSeenGreeting    bool
	queryParams         map[uint32]uint16
	requestBuffer       *packet.Buffer
	responseBuffer      *packet.Buffer
	readsCompleted      int
	decoded             bool
	mu                  sync.Mutex
}

func NewBuilder(
	address structure.ConnectionAddress,
	readers *MySQLConnectionReaders,
) *MySQLConnectionBuilder {
	return &MySQLConnectionBuilder{
		Address:        address,
		Readers:        readers,
		requestBuffer:  &packet.Buffer{},
		responseBuffer: &packet.Buffer{},
		queryParams:    make(map[uint32]uint16),
	}
}

func (b *MySQLConnectionBuilder) AddToConnection(
	request bool, seen []time.Time, typeName string, item interface{},
) {
	t := structure.Transmission{Data: item, Seen: seen}
	if request {
		b.Requests = append(b.Requests, t)
		// FIXME: could this be problematic?
		// how do we know that this sync's with the processing of the
		// other side.  For instance, could we have read all the requests, then
		// read all the responses?
		b.previousRequestType = typeName
	} else {
		b.Responses = append(b.Responses, t)
		b.justSeenGreeting = typeName == "Greeting"
		if typeName == "PREPARE_OK" {
			if rawPacket, ok := item.(structure.WithRawPacket); ok {
				item = rawPacket.Transmission
			}
			// might be neat to store more info, and also be able to join up to
			// the query too.
			prepare := item.(structure.PrepareOKResponse)
			b.queryParams[prepare.StatementID] = prepare.NumParams
		}
	}
}

func (b *MySQLConnectionBuilder) Connection(noSort bool) structure.Connection {
	b.DecodeConnection()

	var items []structure.Transmission
	items = append(items, b.Requests...)
	items = append(items, b.Responses...)

	if !noSort {
		sort.Slice(items, func(i, j int) bool {
			if len(items[i].Seen) > 0 && len(items[j].Seen) > 0 {
				return items[i].Seen[0].Before(items[j].Seen[0])
			} else if len(items[i].Seen) > 0 {
				return true
			}
			return false
		})
	}

	return structure.Connection{
		Address: b.Address,
		Items:   items,
	}
}

func (b *MySQLConnectionBuilder) DecodeConnection() {
	b.mu.Lock()
	fmt.Println("Decode start")
	defer b.mu.Unlock()
	if b.decoded {
		return
	}

	var reqE, resE Emitter
	reqE = &TransmissionEmitter{
		Request: true,
		Times:   b.requestBuffer,
		Builder: b,
	}
	resE = &TransmissionEmitter{
		Request: false,
		Times:   b.responseBuffer,
		Builder: b,
	}

	var requestDecoder, responseDecoder io.Writer
	rqd := &RequestDecoder{Emit: reqE}
	requestDecoder = rqd
	resd := &ResponseDecoder{Emit: resE}
	responseDecoder = resd

	if b.Readers.RawData {
		requestDecoder, rqd.Emit = SetupRawDataEmitter(rqd.Emit, requestDecoder)
		responseDecoder, resd.Emit = SetupRawDataEmitter(resd.Emit, responseDecoder)
	}

	// now loop through the packets and emit
	// them to the decoders in order we saw
	// them.
	var requestPacket, responsePacket *packet.Packet

	reqReader, reqWriter := io.Pipe()
	resReader, resWriter := io.Pipe()
	go func() {
		fmt.Println("Copy req")
		if _, err := packet.Copy(reqReader, requestDecoder); err != nil {
			fmt.Println("Read request error: ", err)
			rqd.Emit.Transmission("DECODE_ERROR",
				structure.DecodeError{
					DecodeError:       err,
					DecodeErrorString: err.Error(),
					Direction:         "Request",
					JustSeenGreeting:  b.justSeenGreeting,
					Packet:            requestPacket,
				},
			)
		}
		fmt.Println("Done reading req")
		reqReader.Close()
	}()
	go func() {
		fmt.Println("Copy res")
		if _, err := packet.Copy(resReader, responseDecoder); err != nil {
			fmt.Println("Read response error: ", err)
			rqd.Emit.Transmission("DECODE_ERROR",
				structure.DecodeError{
					DecodeError:         err,
					DecodeErrorString:   err.Error(),
					Direction:           "Response",
					Packet:              responsePacket,
					PreviousRequestType: b.previousRequestType,
				},
			)
		}
		fmt.Println("Done reading res")
		resReader.Close()
	}()

	fmt.Println("Start loop")
	for {
		fmt.Println("loop")
		requestPacket = b.requestBuffer.CurrentPacket()
		responsePacket = b.responseBuffer.CurrentPacket()

		if responsePacket == nil && requestPacket == nil {
			break
		}

		var writeRequest, writeResponse bool
		switch {
		case responsePacket == nil:
			writeRequest = true
		case requestPacket == nil:
			writeResponse = true
		case responsePacket.FirstSeen().Before(requestPacket.FirstSeen()):
			writeResponse = true
		default:
			writeRequest = true
		}

		switch {
		case writeRequest:
			fmt.Println("Write request")
			if _, err := reqWriter.Write(requestPacket.Data); err != nil {
				fmt.Println("Write request error: ", err)
				rqd.Emit.Transmission("DECODE_ERROR",
					structure.DecodeError{
						DecodeError:       err,
						DecodeErrorString: err.Error(),
						Direction:         "Request",
						JustSeenGreeting:  b.justSeenGreeting,
						Packet:            requestPacket,
					},
				)
			}
			b.requestBuffer.Next()
		case writeResponse:
			fmt.Println("Write response")
			if _, err := resWriter.Write(responsePacket.Data); err != nil {
				fmt.Println("Write response error: ", err)
				resd.Emit.Transmission("DECODE_ERROR",
					structure.DecodeError{
						DecodeError:         err,
						DecodeErrorString:   err.Error(),
						Direction:           "Response",
						Packet:              responsePacket,
						PreviousRequestType: b.previousRequestType,
					},
				)
			}
			b.responseBuffer.Next()
		default:
			panic("wat")
		}
	}
	fmt.Println("Loop complete done writing")
	reqWriter.Close()
	resWriter.Close()
	resd.FlushResponse()
	b.decoded = true
	// don't need to hang onto these.
	b.requestBuffer = nil
	b.responseBuffer = nil
	fmt.Println("Decode complete")
}

func (b *MySQLConnectionBuilder) PreviousRequestType() string {
	return b.previousRequestType
}

func (b *MySQLConnectionBuilder) JustSeenGreeting() bool {
	return b.justSeenGreeting
}

func (b *MySQLConnectionBuilder) ParamsForQuery(query uint32) uint16 {
	if params, ok := b.queryParams[query]; ok {
		return params
	}
	return 0
}

func (b *MySQLConnectionBuilder) ResponsePacketBuffer(t packet.TimesSeen) *packet.Buffer {
	b.responseBuffer.SetTimes(t)
	return b.responseBuffer
}

func (b *MySQLConnectionBuilder) RequestPacketBuffer(t packet.TimesSeen) *packet.Buffer {
	b.requestBuffer.SetTimes(t)
	return b.requestBuffer
}

func (b *MySQLConnectionBuilder) ReadDone() {
	b.mu.Lock()
	b.readsCompleted++
	b.mu.Unlock()
	if b.readsCompleted == bothSides {
		b.DecodeConnection()
	}
}
