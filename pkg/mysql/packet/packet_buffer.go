package packet

import (
	"time"
)

type TimesSeen interface {
	Reset()
	Seen() []time.Time
}

// Packet MySQL packet along with when it was seen.
type Packet struct {
	Seen []time.Time
	Data []byte
}

// Buffer buffers MySQL packets along with their times seen so they can
// be played back in order.
type Buffer struct {
	Times   TimesSeen
	packets []Packet
}

// Write buffers up the packets and stores when they were seen.
func (b *Buffer) Write(p []byte) (n int, err error) {
	packet := Packet{Data: p, Seen: b.Times.Seen()}
	b.Times.Reset()
	if len(packet.Seen) == 0 {
		lastPacket := len(b.packets) - 1
		if lastPacket >= 0 {
			// assume it must have come in at the same time as the previous
			// packet.
			packet.Seen = b.packets[lastPacket].Seen
		}
	}
	b.packets = append(b.packets, packet)
	return len(p), nil
}
