package packet

import "encoding/binary"

// SplitPacket takes a blob of data and divides it up into MySQL packets.  This
// allows for data captured to be sent to regular parsing routines in a way
// that allows them to just consider a packet at a time.  Note that it doesn't
// really do any serious validation.
// Returns a list of packets, plus whatever data appears to remain.
func SplitPacket(data []byte) ([][]byte, []byte) {
	var packets [][]byte

	var lengthBuffer [4]byte
	copy(lengthBuffer[:], data[:3])
	// NOTE: mysql docs say int, and don't appear to mention sign at all, so
	// this is currently just an assumption.
	length := binary.LittleEndian.Uint32(lengthBuffer[:])

	for length > 0 {
		if int(length) <= len(data) {
			packet := data[:4+length]
			data = data[4+length:]
			packets = append(packets, packet)
		} else {
			break
		}

		if len(data) < 4 {
			break
		}
		copy(lengthBuffer[:], data[:3])
		length = binary.LittleEndian.Uint32(lengthBuffer[:])
	}

	return packets, data
}
