package reader

import (
	"io"
	"sync"
	"time"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type MySQLConversationReaders struct {
	mu            sync.Mutex
	conversations map[ConversationAddress]*Conversation
}

type ConversationAddress struct {
	IP, Port gopacket.Flow
}

type Conversation struct {
	Address ConversationAddress
	Items   []Transmission
}

type Transmission struct {
	Data interface{}
	Seen []time.Time
}

func New() *MySQLConversationReaders {
	conversations := make(map[ConversationAddress]*Conversation)
	return &MySQLConversationReaders{
		conversations: conversations,
	}
}

func (h *MySQLConversationReaders) GetConversations() []Conversation {
	conversations := make([]Conversation, len(h.conversations))
	for _, c := range h.conversations {
		conversations = append(conversations, *c)
	}
	return conversations
}

type Stream interface {
	Read(p []byte) (n int, err error)
	Seen() (time.Time, error)
}

type streamDecoder func(*SavePointReader, *TimeCaptureReader, gopacket.Flow, gopacket.Flow) error

func drain(spr *SavePointReader, _ *TimeCaptureReader, _, _ gopacket.Flow) error {
	tcpreader.DiscardBytesToEOF(spr)
	return nil
}

// ReadStream tries to read tcp connections and extract MySQL conversations.
func (h *MySQLConversationReaders) ReadStream(r Stream, a, b gopacket.Flow) {
	t := NewTimeCaptureReader(r)
	spr := NewSavePointReader(t)
	src, dest := b.Endpoints()
	decoders := [2]streamDecoder{}
	if src.LessThan(dest) {
		// assume response
		decoders[0] = h.ReadMySQLResponse
	} else {
		// assume request
		decoders[0] = h.ReadMySQLRequest
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
	spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow,
) error {
	interpreter := decoding.MySQLresponse{}

	if _, err := packet.Copy(spr, &interpreter); err != nil {
		return err
	}
	h.updateResponse(a.Reverse(), b.Reverse(), &interpreter, t.Seen())

	return nil
}

// ReadMySQLRequest try to read the stream as an MySQL request.
func (h *MySQLConversationReaders) ReadMySQLRequest(
	spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow,
) error {
	interpreter := decoding.MySQLRequest{}

	if _, err := packet.Copy(spr, &interpreter); err != nil {
		return err
	}
	h.updateResponse(a, b, &interpreter, t.Seen())

	return nil
}

func (h *MySQLConversationReaders) updateResponse(a, b gopacket.Flow, item interface{}, seen []time.Time) {
	address := ConversationAddress{IP: a, Port: b}
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.conversations[address]
	if !ok {
		c = &Conversation{
			Address: address,
		}
		h.conversations[address] = c
	}
	c.Items = append(c.Items, Transmission{Data: item, Seen: seen})
}
