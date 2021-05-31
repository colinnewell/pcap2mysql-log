package packet

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
)

// Copy transfer from a reader to a writer expecting to receive a packet of
// MySQL data at a time.  Makes use of the MySQLPacketWriter to even out the
// data.
func Copy(rdr io.Reader, wrt io.Writer) (int, error) {
	var read [2048]byte
	var buf bytes.Buffer

	m := MySQLPacketWriter{Receiver: wrt}

	copied := 0
	n, err := rdr.Read(read[:])

	var writeError error
	for err == nil && n > 0 {
		buf.Write(read[:n])
		var w int
		w, writeError = m.Write(buf.Bytes())

		copied += w
		if writeError != nil {
			if !errors.Is(writeError, ErrIncompletePacket) {
				break
			}
		}
		if w > 0 {
			// suck up the data
			buf.Next(w)
		}

		// err checked as we come back around in the for loop.
		n, err = rdr.Read(read[:])
	}

	if writeError != nil {
		// if we had an incomplete packet error, return that
		return copied, writeError
	}

	return copied, err
}
