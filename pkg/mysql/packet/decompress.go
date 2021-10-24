package packet

import (
	"bytes"
	"compress/zlib"
	"io/ioutil"
)

const compressedHeaderLen = 7

func decompressPacket(data []byte) ([]byte, int, error) {
	if len(data) < compressedHeaderLen {
		return []byte(nil), 0, ErrIncompletePacket
	}

	compLength := mySQLPacketLength(data[:3])
	unCompLength := mySQLPacketLength(data[4:6])

	if len(data) < compressedHeaderLen+int(compLength) {
		return []byte(nil), 0, ErrIncompletePacket
	}
	dataBlock := data[compressedHeaderLen : compressedHeaderLen+compLength]
	if unCompLength == 0 {
		// move the data we want into the decompressPacket buffer
		return dataBlock, int(compressedHeaderLen + compLength), nil
	}

	compressedData := bytes.NewBuffer(dataBlock)

	// this is confusing, looking at the docs since MySQL mentioned
	// RFC 1951, and Go mentions 1950 with this library, but
	// also has flate which mentioned 1951, you'd expect that was the
	// library to use.  In practice this seems to be the correct
	// one however.
	zr, err := zlib.NewReader(compressedData)
	if err != nil {
		return []byte(nil), 0, err
	}
	defer zr.Close()
	enflated, err := ioutil.ReadAll(zr)

	return enflated, int(compressedHeaderLen + compLength), err
}
