package packet

import (
	"bytes"
	"compress/zlib"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
)

type MySQLPacketDecompressor struct {
	Receiver io.Writer
}

const compressedHeaderLen = 7

func (w *MySQLPacketDecompressor) Write(data []byte) (int, error) {
	// FIXME: there can be mutliple compressed packets
	// that make up a single uncompressed packet
	// we need a certain amount of state management to deal with
	// that.
	var err error
	var copied int
	b := bytes.NewBuffer(data)
	var decompressed bytes.Buffer
	for {
		var n int
		err = decompressPacket(b, &decompressed)
		if err != nil {
			return copied, err
		}
		if decompressed.Len() > 0 {
			n, err = Copy(&decompressed, w.Receiver)
			copied += n
			if err == io.EOF {
				// this is fine.
				err = nil
			}
		}
		if b.Len() == 0 {
			// nothing left to do
			break
		}
		if err != nil && !errors.Is(err, ErrIncompletePacket) {
			return copied, err
		}
	}
	return copied, err
}

func decompressPacket(b *bytes.Buffer, decompressed *bytes.Buffer) error {
	if b.Len() < compressedHeaderLen {
		return ErrIncompletePacket
	}

	header := [compressedHeaderLen]byte{}

	if _, err := b.Read(header[:]); err != nil {
		return err
	}
	compLength := mySQLPacketLength(header[:3])
	unCompLength := mySQLPacketLength(header[4:6])

	if b.Len() < int(compLength) {
		return ErrIncompletePacket
	}

	if unCompLength == 0 {
		// move the data we want into the decompressPacket buffer
		if _, err := decompressed.Write(b.Next(int(compLength))); err != nil {
			return err
		}

		return nil
	}

	compressedData := bytes.NewBuffer(b.Next(int(compLength)))

	// this is confusing, looking at the docs since MySQL mentioned
	// RFC 1951, and Go mentions 1950 with this library, but
	// also has flate which mentioned 1951, you'd expect that was the
	// library to use.  In practice this seems to be the correct
	// one however.
	zr, err := zlib.NewReader(compressedData)
	if err != nil {
		return err
	}
	defer zr.Close()
	enflated, err := ioutil.ReadAll(zr)
	if err != nil {
		return err
	}

	if _, err := decompressed.Write(enflated); err != nil {
		return err
	}

	return nil
}
