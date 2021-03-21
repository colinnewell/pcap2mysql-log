package decoding

import (
	"sort"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
)

type ConnectionBuilder interface {
	AddToConnection(
		request bool, seen []time.Time, typeName string, item interface{},
	)
	JustSeenGreeting() bool
	PreviousRequestType() string
}

type MySQLConnectionBuilder struct {
	Address             structure.ConnectionAddress
	Readers             *MySQLConnectionReaders
	Requests            []structure.Transmission
	Responses           []structure.Transmission
	previousRequestType string
	justSeenGreeting    bool
}

func (b *MySQLConnectionBuilder) AddToConnection(
	request bool, seen []time.Time, typeName string, item interface{},
) {
	t := structure.Transmission{Data: item, Seen: seen}
	if request {
		b.Requests = append(b.Requests, t)
		b.previousRequestType = typeName
	} else {
		b.Responses = append(b.Responses, t)
		b.justSeenGreeting = typeName == "Greeting"
	}
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
	return b.previousRequestType
}

func (b *MySQLConnectionBuilder) JustSeenGreeting() bool {
	return b.justSeenGreeting
}
