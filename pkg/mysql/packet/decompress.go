package packet

import (
	"bytes"
	"compress/zlib"
	"io"
	"io/ioutil"
)

type MySQLPacketDecompressor struct {
	Receiver io.Writer
}

const compressedHeaderLen = 7

func (w *MySQLPacketDecompressor) Write(data []byte) (int, error) {
	if len(data) < compressedHeaderLen {
		return 0, ErrIncompletePacket
	}

	compLength := mySQLPacketLength(data[:3])
	unCompLength := mySQLPacketLength(data[4:6])

	if len(data) < compressedHeaderLen+int(compLength) {
		return 0, ErrIncompletePacket
	}

	dataBlock := data[compressedHeaderLen : compressedHeaderLen+compLength]
	if unCompLength == 0 {
		// not compressed, just strip off the extra header
		n, err := w.Receiver.Write(dataBlock)
		return n + compressedHeaderLen, err
	}

	b := bytes.NewBuffer(dataBlock)

	// this is confusing, looking at the docs since MySQL mentioned
	// RFC 1951, and Go mentions 1950 with this library, but
	// also has flate which mentioned 1951, you'd expect that was the
	// library to use.  In practice this seems to be the correct
	// one however.
	zr, err := zlib.NewReader(b)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	enflated, err := ioutil.ReadAll(zr)
	if err != nil {
		return 0, err
	}

	n, err := Copy(bytes.NewBuffer(enflated), w.Receiver)
	return n + compressedHeaderLen, err
}
