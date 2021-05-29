package decoding

import (
	"sort"
	"sync"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
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
	previousRequestType []string
	justSeenGreeting    []bool
	queryParams         map[uint32]uint16
	observers           TransmissionObserverList
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
		b.previousRequestType = append(b.previousRequestType, typeName)
	} else {
		b.Responses = append(b.Responses, t)
		b.justSeenGreeting = append(b.justSeenGreeting, typeName == "Greeting")
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
	b.observers.TransmissionAdded()
}

func (b *MySQLConnectionBuilder) Connection() structure.Connection {
	items := append(b.Requests, b.Responses...)

	sort.Slice(items, func(i, j int) bool {
		if len(items[i].Seen) > 0 && len(items[j].Seen) > 0 {
			return items[i].Seen[0].Before(items[j].Seen[0])
		} else if len(items[i].Seen) > 0 {
			return true
		}
		return false
	})

	return structure.Connection{
		Address: b.Address,
		Items:   items,
	}
}

func (b *MySQLConnectionBuilder) PreviousRequestType() string {
	o := b.observers.AddObserver(&b.Requests, &b.Responses)
	i := o.NextTransmission()

	if i >= len(b.previousRequestType) {
		return ""
	}

	return b.previousRequestType[i]
}

func (b *MySQLConnectionBuilder) JustSeenGreeting() bool {
	if len(b.justSeenGreeting) == 0 {
		return false
	}

	return b.justSeenGreeting[len(b.justSeenGreeting)-1]
}

func (b *MySQLConnectionBuilder) ParamsForQuery(query uint32) uint16 {
	if params, ok := b.queryParams[query]; ok {
		return params
	}
	return 0
}

type TransmissionObserverList struct {
	observers []*TransmissionObserver
}

func (l *TransmissionObserverList) TransmissionAdded() {
	for _, o := range l.observers {
		o.TransmissionAdded()
	}
}

func (l *TransmissionObserverList) AddObserver(need *[]structure.Transmission, have *[]structure.Transmission) *TransmissionObserver {
	o := NewTransmissionObserver(need, have)
	l.observers = append(l.observers, o)
	return o
}

type TransmissionObserver struct {
	a  *[]structure.Transmission
	b  *[]structure.Transmission
	wg sync.WaitGroup
}

func NewTransmissionObserver(need *[]structure.Transmission, have *[]structure.Transmission) *TransmissionObserver {
	return &TransmissionObserver{a: need, b: have}
}

func (o *TransmissionObserver) TransmissionAdded() {
	o.wg.Done()
}

func (o *TransmissionObserver) NextTransmission() int {
	// wait until next one appears
	// FIXME: would I be better with channels?
	// and perhaps a timeout
	i := len(*o.b)
	for i < len(*o.a) {
		o.wg.Add(1)
		// wait for request to come in
		o.wg.Wait()
	}
	return i
}
