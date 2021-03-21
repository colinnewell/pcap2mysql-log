package decoding

import (
	"sort"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
)

// FIXME: this is massively different currently.
// also, is it needed?
type ConnectionBuilder interface {
	DecodedResponse(t interface{})
	DecodedRequest(typeName string, t interface{})
	JustSeenGreeting() bool
	PreviousRequestType() string
}

type MySQLConnectionBuilder struct {
	Address   structure.ConnectionAddress
	Readers   *MySQLConnectionReaders
	Requests  []structure.Transmission
	Responses []structure.Transmission
}

func (b *MySQLConnectionBuilder) AddToConnection(
	request bool, seen []time.Time, item interface{},
) {
	t := structure.Transmission{Data: item, Seen: seen}
	if request {
		b.Requests = append(b.Requests, t)
	} else {
		b.Responses = append(b.Responses, t)
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
