package packet

import (
	"time"
)

// TimesSeen interface for something that gathers the times that data was seen.
// Due to the nature of how ip packets and then mysql packets, and then
// 'requests' and 'responses' etc. may not have a one to one relationship there
// may be multiple time stamps associated with parts of the data.
type TimesSeen interface {
	Reset()
	Seen() []time.Time
}

// Packet MySQL packet along with when it was seen.
type Packet struct {
	Seen []time.Time
	Data []byte
}

func (p Packet) FirstSeen() time.Time {
	if len(p.Seen) > 0 {
		return p.Seen[0]
	}
	return time.Time{}
}

// Buffer buffers MySQL packets along with their times seen so they can
// be played back in order.
type Buffer struct {
	times   TimesSeen
	packets []Packet
	pos     int
}

func (b *Buffer) SetTimes(t TimesSeen) {
	b.times = t
}

// Write buffers up the packets and stores when they were seen.
func (b *Buffer) Write(p []byte) (n int, err error) {
	packet := Packet{Data: p, Seen: b.times.Seen()}
	b.times.Reset()
	if len(packet.Seen) == 0 {
		lastPacket := len(b.packets) - 1
		if lastPacket >= 0 {
			// assume it must have come in at
			// the same time as the previous
			// packet.
			packet.Seen = b.packets[lastPacket].Seen
		}
	}
	b.packets = append(b.packets, packet)
	return len(p), nil
}

func (b *Buffer) CurrentPacket() *Packet {
	if b.pos >= len(b.packets) {
		return nil
	}

	return &b.packets[b.pos]
}

func (b *Buffer) Next() {
	b.pos++
}

func (*Buffer) Reset() {
	// FIXME: this is awkward.  This is wanted for the times seen thing
}

func (b *Buffer) Seen() []time.Time {
	p := b.CurrentPacket()
	if p == nil {
		return []time.Time{}
	}
	return p.Seen
}
