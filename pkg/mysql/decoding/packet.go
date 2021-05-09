package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/pkg/errors"
)

var errRequestTooManyBytes = errors.New("requesting more bytes than are in the packet")
var errRequestTooFewBytes = errors.New("not enough bytes")

// FIXME: does date have time set to 0 or actually just take this much?
type date struct {
	Length uint8
	Year   uint16
	Month  uint8
	Day    uint8
}

type timeS struct {
	Hour    uint8
	Minutes uint8
	Seconds uint8
}

type timeMs struct {
	timeS
	MicroSeconds uint32
}

type dateTime struct {
	date
	timeS
}

type dateTimeMs struct {
	date
	timeMs
}

type timeInfo struct {
	Length   uint8
	Negative uint8
	Date     uint32
	Hour     uint8
	Minutes  uint8
	Seconds  uint8
}

type timeInfoMs struct {
	timeInfo
	MicroSeconds uint32
}

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

func readLenEncInt(buf io.Reader) (uint64, error) {
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

func readType(buf *bytes.Buffer, fieldType structure.FieldType) (interface{}, error) {
	switch fieldType {
	case structure.FLOAT:
		var val float32
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		return val, nil
		// FLOAT is the IEEE 754 floating-point value in Little-endian format on 4 bytes.
	case structure.DOUBLE:
		var val float64
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		return val, nil
		// DOUBLE is the IEEE 754 floating-point value in Little-endian format on 8 bytes.
	case structure.LONGLONG:
		// FIXME: need to determine if this is signed.
		// probably in ParamFlag, need to figure out exactly what to pick out.
		var val int64
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		return val, nil
	case structure.INT24:
		// FIXME: need to determine if this is signed.
		data := [INT24Width]byte{}
		if n, err := buf.Read(data[:]); err != nil {
			if n < INT24Width {
				return nil, errors.Wrap(errRequestTooFewBytes, "reading int24 for execute")
			}
			return nil, errors.Wrap(err, "decode-execute")
		}
		val, _ := binary.Varint(data[:])
		// FIXME: do I need to deal with endianness now?
		return val, nil

	case structure.LONG:
		// FIXME: need to determine if this is signed.
		// probably in ParamFlag, need to figure out exactly what to pick out.
		var val int32
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		return val, nil
	case structure.SHORT,
		// FIXME: need to determine if this is signed.
		structure.YEAR:
		var val int16
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		return val, nil

	case structure.TINY:
		var val int8
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		return val, nil

	case structure.DATE,
		structure.DATETIME,
		structure.TIMESTAMP:
		var d date
		if err := binary.Read(buf, binary.LittleEndian, &d); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}

		if d.Length == 4 {
			return d, nil
		}
		var t timeS
		if err := binary.Read(buf, binary.LittleEndian, &t); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		if d.Length == 7 {
			return dateTime{
				date:  d,
				timeS: t,
			}, nil
		}
		var ms uint32
		if err := binary.Read(buf, binary.LittleEndian, &ms); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}

		return dateTimeMs{
			date: d,
			timeMs: timeMs{
				timeS:        t,
				MicroSeconds: ms,
			},
		}, nil
		// FIXME: would be good to know locale for timestamp from server info assuming that's provided.
		// byte position	description
		// 1	data length : 4 without hour/minute/second part, 7 without fractional seconds, 11 with fractional seconds
		// 2-3	year on 2 bytes little-endian format
		// 4	Month ( 1=january)
		// 5	days of month

		// 6	hour of day (0 if DATE type)
		// 7	minutes (0 if DATE type)
		// 8	secondes (0 if DATE type)

		// 9-12	micro-second on 4 bytes little-endian format (only if data-length is > 7)

	case structure.TIME:
		var t timeInfo
		if err := binary.Read(buf, binary.LittleEndian, &t); err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}

		if t.Length == 12 {
			// read microseconds
			var ms uint32
			if err := binary.Read(buf, binary.LittleEndian, &ms); err != nil {
				return nil, errors.Wrap(err, "decode-execute")
			}
			return timeInfoMs{timeInfo: t, MicroSeconds: ms}, nil
		}

		return t, nil
		// byte position	description
		// 1	data length : 8 without fractional seconds, 12 with fractional seconds
		// 2	is negative
		// 3-6	date on 4 bytes little-endian format
		// 7	hour of day
		// 8	minutes
		// 9	secondes

		// 10-13	micro-second on 4 bytes little-endian format (only if data-length is > 7)

	case structure.STRING,
		structure.VAR_STRING,
		structure.VARCHAR:

		data, err := readLenEncBytes(buf)
		if err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		return string(data), nil

	case structure.NULL:
		return nil, nil

	default:
		data, err := readLenEncBytes(buf)
		if err != nil {
			return nil, errors.Wrap(err, "decode-execute")
		}
		// FIXME: does it look like text?  If so provide it in text.
		// if not, should we encode it so it's clear it's binary?
		// base64 can be confusing if you're not expecting it.
		if isText(data) {
			return struct{ Text string }{Text: string(data)}, nil
		}
		return struct{ Base64 []byte }{Base64: data}, nil
		// byte<lenenc> encoding
		// starts with length encoded int for length,
		// then we have the bytes
	}
}

func isText(b []byte) bool {
	s := string(b)
	for _, c := range s {
		if !(unicode.IsPrint(c) || unicode.IsSpace(c)) {
			return false
		}
	}
	return true
}
