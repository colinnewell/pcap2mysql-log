package packet

import (
	"encoding/binary"
	er "errors"
	"io"

	"github.com/pkg/errors"
)

// MySQLPacketWriter wraps a writer expecting MySQL packets and ensures that
// writer receives single MySQL packets for each Write call.  Will return an
// error if it can't, or if the underlying writer errors.
type MySQLPacketWriter struct {
	Receiver io.Writer
}

// ErrIncompletePacket the data being written didn't form a complete set of
// packets.  Call aborted when it reached the incomplete packet.
var ErrIncompletePacket = er.New("packet: incomplete packet")

// Write sends complete packets through as individual calls to Write on the
// Receiver.  If there is incomplete data at the end it will return an
// ErrIncompletePacket and the number of bytes it did write.
// Note that the Receiver can also return an error.
func (w *MySQLPacketWriter) Write(data []byte) (n int, err error) {
	var written int

	var lengthBuffer [4]byte
	copy(lengthBuffer[:], data[:3])
	length := binary.LittleEndian.Uint32(lengthBuffer[:])

	for length > 0 {
		if int(length)+4 <= len(data) {
			wrote, err := w.Receiver.Write(data[:4+length])
			written = written + wrote
			if err != nil {
				return written, errors.Wrap(err, "packet write failed")
			}
			data = data[4+length:]
		} else {
			return written, ErrIncompletePacket
		}

		if len(data) < 4 {
			return written, ErrIncompletePacket
		}
		copy(lengthBuffer[:], data[:3])
		length = binary.LittleEndian.Uint32(lengthBuffer[:])
	}

	return written, nil
}