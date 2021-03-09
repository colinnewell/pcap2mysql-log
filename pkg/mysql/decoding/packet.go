package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func readLenEncString(buf *bytes.Buffer) (string, error) {
	count, err := buf.ReadByte()

	if err != nil {
		return "", err
	}

	s := string(buf.Next(int(count)))

	if len(s) < int(count) {
		return "", fmt.Errorf("only read %d bytes", len(s))
	}

	return s, nil
}

func readNulString(buf *bytes.Buffer) (string, error) {
	vb, err := buf.ReadBytes(0)
	if err != nil {
		return "", err
	}
	return string(vb[:len(vb)-1]), nil
}

func readLenEncBytes(buf *bytes.Buffer) ([]byte, error) {
	length, err := readLenEncInt(buf)
	if err != nil {
		return []byte(nil), err
	}

	if length > uint64(buf.Len()) {
		return []byte(nil),
			fmt.Errorf(
				"length encoded field requesting more bytes than are in the packet: %d wanted, %d left",
				length, buf.Len())
	}
	data := make([]byte, length)
	if _, err := buf.Read(data); err != nil {
		return []byte(nil), err
	}

	return data, err
}

func readLenEncInt(buf io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := buf.Read(first[:]); err != nil {
		return 0, err
	}
	l := first[0]

	switch l {
	case encodedNull:
		// FIXME: actually null, not sure how to express this.
		return 0, nil
	case encoded16bit:
		var val uint16
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case encoded32bit:
		var val uint32
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case encoded64bit:
		var val uint64
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return val, nil
	default:
		return uint64(l), nil
	}
}

// func readFixedString(buf *bytes.Buffer, length int) (string, error) {
// 	b := buf.Next(length)
// 	if len(b) < length {
// 		return "", fmt.Errorf("only read %d bytes", len(b))
// 	}
// 	return string(b), nil
// }
