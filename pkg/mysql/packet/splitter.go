package packet

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
)

// Splitter takes writes for the packets and ensures we emit full
// MySQL packets to the writer provided.  This will buffer up data as
// necessary.  To check if there was left over, call the
// IncompletePacket() function once done writing.
type Splitter struct {
	buf              bytes.Buffer
	writer           io.Writer
	wrappedWriter    io.Writer
	incompletePacket bool
}

func NewSplitter(wrt io.Writer) *Splitter {
	return &Splitter{
		writer:        wrt,
		wrappedWriter: &MySQLPacketWriter{Receiver: wrt},
	}
}

func (c *Splitter) CompressionDetected() {
	c.wrappedWriter = &MySQLPacketDecompressor{Receiver: c.writer}
}

func (c *Splitter) Write(p []byte) (int, error) {
	c.buf.Write(p)
	n, err := c.wrappedWriter.Write(c.buf.Bytes())
	if err != nil {
		if errors.Is(err, ErrIncompletePacket) {
			c.incompletePacket = true
			return n, nil
		}
		return n, err
	}
	if n > 0 {
		// suck up the data
		c.buf.Next(n)
	}
	return n, nil
}

func (c *Splitter) IncompletePacket() bool {
	return c.incompletePacket
}
