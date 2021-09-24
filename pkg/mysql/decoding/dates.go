package decoding

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

// FIXME: does date have time set to 0 or actually just take this much?
type date struct {
	Length uint8
	Year   uint16
	Month  uint8
	Day    uint8
}

func (d date) String() string {
	return fmt.Sprintf("%04d-%02d-%02d",
		d.Year,
		d.Month,
		d.Day,
	)
}

func (d date) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

type timeS struct {
	Hour    uint8
	Minutes uint8
	Seconds uint8
}

func (t timeS) String() string {
	return fmt.Sprintf(
		"%d:%d:%d",
		t.Hour,
		t.Minutes,
		t.Seconds,
	)
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

func (d dateTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf(
		"%s %s",
		d.date.String(),
		d.timeS.String(),
	))
}

func (d dateTimeMs) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf(
		"%s %s.%04d",
		d.date.String(),
		d.timeS.String(),
		d.MicroSeconds,
	))
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

func readDate(buf io.Reader) (interface{}, error) {
	var d date
	if err := binary.Read(buf, binary.LittleEndian, &d); err != nil {
		return nil, errors.Wrap(err, "read-date")
	}

	//nolint:gomnd
	if d.Length == 4 {
		return d, nil
	}
	var t timeS
	if err := binary.Read(buf, binary.LittleEndian, &t); err != nil {
		return nil, errors.Wrap(err, "read-date")
	}
	//nolint:gomnd
	if d.Length == 7 {
		return dateTime{
			date:  d,
			timeS: t,
		}, nil
	}
	var ms uint32
	if err := binary.Read(buf, binary.LittleEndian, &ms); err != nil {
		return nil, errors.Wrap(err, "read-date")
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
}

func readTime(buf io.Reader) (interface{}, error) {
	var t timeInfo
	if err := binary.Read(buf, binary.LittleEndian, &t); err != nil {
		return nil, errors.Wrap(err, "read-time")
	}

	//nolint:gomnd
	if t.Length == 12 {
		// read microseconds
		var ms uint32
		if err := binary.Read(buf, binary.LittleEndian, &ms); err != nil {
			return nil, errors.Wrap(err, "read-time")
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
}
