package reader

import (
	"io"
	"sync"
	"time"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/internal/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type MySQLConversationReaders struct {
	mu            sync.Mutex
	conversations map[types.ConversationAddress]*types.Conversation
}

func New() *MySQLConversationReaders {
	conversations := make(map[types.ConversationAddress]*types.Conversation)
	return &MySQLConversationReaders{
		conversations: conversations,
	}
}

func (h *MySQLConversationReaders) GetConversations() []types.Conversation {
	conversations := make([]types.Conversation, len(h.conversations))
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
	spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow,
) error {
	address := types.ConversationAddress{IP: a.Reverse(), Port: b.Reverse()}
	e := TransmissionEmitter{
		Address: address,
		Times:   t,
	}
	interpreter := decoding.ResponseDecoder{Emit: &e}

	if _, err := packet.Copy(spr, &interpreter); err != nil {
		return err
	}

	return nil
}

// ReadRequestDecoder try to read the stream as an MySQL request.
func (h *MySQLConversationReaders) ReadRequestDecoder(
	spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow,
) error {
	address := types.ConversationAddress{IP: a, Port: b}
	e := TransmissionEmitter{
		Address: address,
		Times:   t,
	}
	interpreter := decoding.RequestDecoder{
		Emit: &e,
	}

	if _, err := packet.Copy(spr, &interpreter); err != nil {
		return err
	}

	return nil
}

type TransmissionEmitter struct {
	Address types.ConversationAddress
	Times   types.TimesSeen
}

func (e *TransmissionEmitter) Transmission(t interface{}) {
}
