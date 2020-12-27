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

	for err == nil {
		buf.Write(read[:n])
		w, err := m.Write(buf.Bytes())

		copied += w
		if errors.Cause(err) != ErrIncompletePacket {
			buf.Reset()
		} else if err != nil {
			return copied, err
		}

		n, err = rdr.Read(read[:])
	}

	return copied, err
}
