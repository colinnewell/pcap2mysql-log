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
	conversations map[ConversationAddress][]Conversation
}

type ConversationAddress struct {
	IP, Port gopacket.Flow
}
type Conversation struct {
	Address      ConversationAddress
	Request      *decoding.MySQLRequest
	Response     *decoding.MySQLresponse
	RequestSeen  []time.Time
	ResponseSeen []time.Time
}

func New() *MySQLConversationReaders {
	conversations := make(map[ConversationAddress][]Conversation)
	return &MySQLConversationReaders{
		conversations: conversations,
	}
}

func (h *MySQLConversationReaders) GetConversations() []Conversation {
	var conversations []Conversation
	for _, c := range h.conversations {
		conversations = append(conversations, c...)
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
	h.addResponse(a, b, &interpreter, t.Seen())

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
	h.addRequest(a, b, &interpreter, t.Seen())

	return nil
}

func (h *MySQLConversationReaders) addRequest(a, b gopacket.Flow, req *decoding.MySQLRequest, seen []time.Time) {
	address := ConversationAddress{IP: a, Port: b}
	h.mu.Lock()
	defer h.mu.Unlock()
	conversations := h.conversations[address]
	for n := 0; n < len(conversations); n++ {
		c := conversations[n]
		if conversations[n].Request == nil {
			c.Request = req
			c.RequestSeen = seen
			h.conversations[address][n] = c
			return
		}
	}
	h.conversations[address] = append(h.conversations[address], Conversation{
		Address:     address,
		Request:     req,
		RequestSeen: seen,
	})
}

func (h *MySQLConversationReaders) addResponse(a, b gopacket.Flow, res *decoding.MySQLresponse, seen []time.Time) {
	h.updateResponse(a, b, func(c *Conversation) {
		c.Response = res
		c.ResponseSeen = seen
	})
}

func (h *MySQLConversationReaders) updateResponse(a, b gopacket.Flow, update func(*Conversation)) {
	address := ConversationAddress{IP: a.Reverse(), Port: b.Reverse()}
	h.mu.Lock()
	defer h.mu.Unlock()
	conversations := h.conversations[address]
	if conversations == nil {
		c := Conversation{
			Address: address,
		}
		update(&c)
		h.conversations[address] = append(h.conversations[address], c)
		return
	}
	for n := 0; n < len(conversations); n++ {
		c := conversations[n]
		if conversations[n].Response == nil {
			update(&c)
			h.conversations[address][n] = c
			break
		}
		// FIXME: should think about what we do when we don't find
		// the other side of the conversation.
	}
}
