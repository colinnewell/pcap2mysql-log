package packet

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
)

func Copy(rdr io.Reader, wrt io.Writer) (int, error) {
	var read [2048]byte
	var buf bytes.Buffer

	m := MySQLPacketWriter{Receiver: wrt}

	copied := 0
	n, err := rdr.Read(read[:])

	for err == nil && n > 0 {
		buf.Write(read[:n])
		w, err := m.Write(buf.Bytes())

		copied += w
		if err != nil && errors.Cause(err) != ErrIncompletePacket {
			return copied, err
		}
		if w > 0 {
			// suck up the data
			buf.Next(w)
		}

		n, err = rdr.Read(read[:])
	}

	return copied, err
}
