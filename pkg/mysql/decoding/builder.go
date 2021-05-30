package decoding

import (
	"sort"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/colinnewell/pcap2mysql-log/pkg/tcp"
)

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
}

func NewBuilder(
	address structure.ConnectionAddress,
	readers *MySQLConnectionReaders,
) *MySQLConnectionBuilder {
	return &MySQLConnectionBuilder{
		Address:     address,
		Readers:     readers,
		queryParams: make(map[uint32]uint16),
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
	items := append(b.Requests, b.Responses...)

	// FIXME: now flush the buffers and decode.

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

func (b *MySQLConnectionBuilder) ResponsePacketBuffer(t *tcp.TimeCaptureReader) *packet.Buffer {
	b.responseBuffer = &packet.Buffer{
		Times: t,
	}
	return b.responseBuffer
}

func (b *MySQLConnectionBuilder) RequestPacketBuffer(t *tcp.TimeCaptureReader) *packet.Buffer {
	b.requestBuffer = &packet.Buffer{
		Times: t,
	}
	return b.requestBuffer
}
