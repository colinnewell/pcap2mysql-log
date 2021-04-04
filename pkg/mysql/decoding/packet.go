package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
)

var errRequestTooManyBytes = errors.New("requesting more bytes than are in the packet")
var errRequestTooFewBytes = errors.New("not enough bytes")

func readLenEncString(buf *bytes.Buffer) (string, error) {
	count, err := buf.ReadByte()

	if err != nil {
		return "", errors.Wrap(err, "read-len-enc-string")
	}

	s := string(buf.Next(int(count)))

	if len(s) < int(count) {
		return "",
			errors.Wrap(
				errRequestTooFewBytes,
				fmt.Sprintf("only read %d bytes", len(s)),
			)
	}

	return s, nil
}

func readNulString(buf *bytes.Buffer) (string, error) {
	vb, err := buf.ReadBytes(0)
	if err != nil {
		return "", errors.Wrap(err, "read-nul-string")
	}
	return string(vb[:len(vb)-1]), nil
}

func readLenEncBytes(buf *bytes.Buffer) ([]byte, error) {
	length, err := readLenEncInt(buf)
	if err != nil {
		return []byte(nil), errors.Wrap(err, "read-len-enc-bytes")
	}

	if length > uint64(buf.Len()) {
		return []byte(nil),
			errors.Wrap(
				errRequestTooManyBytes,
				fmt.Sprintf("%d wanted, %d left", length, buf.Len()),
			)
	}
	data := make([]byte, length)
	if _, err := buf.Read(data); err != nil {
		return []byte(nil), errors.Wrap(err, "read-len-enc-bytes")
	}

	return data, err
}

func readLenEncInt(buf *bytes.Buffer) (uint64, error) {
	var first [1]byte
	if _, err := buf.Read(first[:]); err != nil {
		return 0, errors.Wrap(err, "read-len-enc-int")
	}
	l := first[0]

	switch l {
	case encodedNull:
		// FIXME: actually null, not sure how to express this.
		return 0, nil
	case encoded16bit:
		var val uint16
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, errors.Wrap(err, "read-len-enc-int")
		}
		return uint64(val), nil
	case encoded32bit:
		var val uint32
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, errors.Wrap(err, "read-len-enc-int")
		}
		return uint64(val), nil
	case encoded64bit:
		var val uint64
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, errors.Wrap(err, "read-len-enc-int")
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
