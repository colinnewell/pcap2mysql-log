package packet

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
)

// PacketSplitter takes writes for the packets and ensures we emit full
// MySQL packets to the writer provided.  This will buffer up data as
// necessary.  To check if there was left over, call the
// IncompletePacket() function once done writing.
type PacketSplitter struct {
	buf              bytes.Buffer
	writer           io.Writer
	wrappedWriter    io.Writer
	incompletePacket bool
}

func NewPacketSplitter(wrt io.Writer) *PacketSplitter {
	return &PacketSplitter{
		writer:        wrt,
		wrappedWriter: &MySQLPacketWriter{Receiver: wrt},
	}
}

func (c *PacketSplitter) CompressionDetected() {
	c.wrappedWriter = &MySQLPacketDecompressor{Receiver: c.writer}
}

func (c *PacketSplitter) Write(p []byte) (n int, err error) {

	var writeError error
	c.buf.Write(p[:n])
	var w int
	w, writeError = c.wrappedWriter.Write(c.buf.Bytes())

	if writeError != nil {
		if errors.Is(writeError, ErrIncompletePacket) {
			c.incompletePacket = true
			return w, nil
		}
	}
	if w > 0 {
		// suck up the data
		c.buf.Next(w)
	}

	if writeError != nil {
		// if we had an incomplete packet error, return that
		return w, writeError
	}

	return w, err
}

func (c *PacketSplitter) IncompletePacket() bool {
	return c.incompletePacket
}
