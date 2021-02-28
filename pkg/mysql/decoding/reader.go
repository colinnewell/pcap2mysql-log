package decoding

import (
	"bytes"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/colinnewell/pcap2mysql-log/pkg/tcp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type Emitter interface {
	Transmission(t interface{})
}

type TimesSeen interface {
	Reset()
	Seen() []time.Time
}

type MySQLConversationReaders struct {
	mu            sync.Mutex
	conversations map[structure.ConversationAddress]*structure.Conversation
	rawData       bool
}

func New(rawData bool) *MySQLConversationReaders {
	conversations := make(map[structure.ConversationAddress]*structure.Conversation)
	return &MySQLConversationReaders{
		conversations: conversations,
		rawData:       rawData,
	}
}

func (h *MySQLConversationReaders) GetConversations() []structure.Conversation {
	conversations := make([]structure.Conversation, len(h.conversations))
	i := 0
	for _, c := range h.conversations {
		sort.Slice(c.Items, func(i, j int) bool {
			if len(c.Items[i].Seen) > 0 && len(c.Items[j].Seen) > 0 {
				return c.Items[i].Seen[0].Before(c.Items[j].Seen[0])
			} else if len(c.Items[i].Seen) > 0 {
				return true
			}
			return false
		})
		conversations[i] = *c
		i++
	}
	sort.Slice(conversations, func(i, j int) bool {
		return conversations[i].Items[0].Seen[0].Before(conversations[j].Items[0].Seen[0])
	})
	return conversations
}

func (h *MySQLConversationReaders) AddConversation(
	address structure.ConversationAddress, seen []time.Time, item interface{},
) {
	h.mu.Lock()
	defer h.mu.Unlock()

	c, ok := h.conversations[address]
	if !ok {
		c = &structure.Conversation{
			Address: address,
		}
		h.conversations[address] = c
	}
	c.Items = append(c.Items, structure.Transmission{Data: item, Seen: seen})
}

type streamDecoder func(io.Reader, *tcp.TimeCaptureReader, gopacket.Flow, gopacket.Flow) error

func drain(spr io.Reader, _ *tcp.TimeCaptureReader, _, _ gopacket.Flow) error {
	tcpreader.DiscardBytesToEOF(spr)
	return nil
}

// ReadStream tries to read tcp connections and extract MySQL conversations.
func (h *MySQLConversationReaders) ReadStream(r tcp.Stream, a, b gopacket.Flow) {
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
func (h *MySQLConversationReaders) ReadMySQLResponse(
	spr io.Reader, t *tcp.TimeCaptureReader, a, b gopacket.Flow,
) error {
	address := structure.ConversationAddress{IP: a.Reverse(), Port: b.Reverse()}
	var e Emitter
	e = &TransmissionEmitter{
		Address: address,
		Times:   t,
		Readers: h,
	}
	if h.rawData {
		spr, e = SetupRawDataEmitter(e, spr)
	}
	interpreter := ResponseDecoder{Emit: e}

	if _, err := packet.Copy(spr, &interpreter); err != nil {
		return err
	}
	interpreter.FlushResponse()

	return nil
}

// ReadRequestDecoder try to read the stream as an MySQL request.
func (h *MySQLConversationReaders) ReadRequestDecoder(
	spr io.Reader, t *tcp.TimeCaptureReader, a, b gopacket.Flow,
) error {
	address := structure.ConversationAddress{IP: a, Port: b}
	var e Emitter
	e = &TransmissionEmitter{
		Address: address,
		Times:   t,
		Readers: h,
	}
	if h.rawData {
		spr, e = SetupRawDataEmitter(e, spr)
	}
	interpreter := RequestDecoder{
		Emit: e,
	}

	if _, err := packet.Copy(spr, &interpreter); err != nil {
		return err
	}

	return nil
}

type TransmissionEmitter struct {
	Address structure.ConversationAddress
	Times   TimesSeen
	Readers *MySQLConversationReaders
}

func (e *TransmissionEmitter) Transmission(t interface{}) {
	e.Readers.AddConversation(e.Address, e.Times.Seen(), t)
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
	e.emitter.Transmission(structure.WithRawPacket{RawData: e.read.Bytes(), Transmission: t})
	e.read.Reset()
}
