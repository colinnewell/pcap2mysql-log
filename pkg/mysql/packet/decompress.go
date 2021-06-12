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

func (w *MySQLPacketDecompressor) Write(data []byte) (int, error) {
	compLength := mySQLPacketLength(data[:3])
	unCompLength := mySQLPacketLength(data[4:6])
	dataBlock := data[7 : 7+compLength]
	if unCompLength == 0 {
		// not compressed, just strip off the extra header
		n, err := w.Receiver.Write(dataBlock)
		return n + 7, err
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
	return n + 7, err
}