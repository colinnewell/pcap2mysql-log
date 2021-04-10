package bitmap

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
)

var errReadPastEnd = errors.New("attempt to read past end of bitmap")

const ResultSetRow = 9
const ExecuteParams = 7

type NullBitMap struct {
	Data   []byte
	Width  int
	Params int
}

func New(data []byte, params int, width int) *NullBitMap {
	return &NullBitMap{Data: data, Params: params, Width: width}
}

func ReadNullMap(buf *bytes.Buffer, paramCount int, width int) (*NullBitMap, error) {
	neededBytes := (paramCount + width) / 8
	data := make([]byte, neededBytes)

	if _, err := buf.Read(data); err != nil {
		return nil, errors.Wrap(err, "failed to read nullmap")
	}

	return New(data, paramCount, width), nil
}

func (nm *NullBitMap) IsNull(column int) bool {
	// FIXME: am I picking out the correct bit?
	// expecting column to start at 0
	if column >= nm.Params {
		panic(errReadPastEnd)
	}

	var bitWidth, offset int

	if nm.Width == ExecuteParams {
		bitWidth = 8
		offset = 0
		// simple figure out byte then bit
	} else {
		bitWidth = 6
		offset = 2
		// data starts at bit 3 (what are the first 2 ?)
	}

	bit := column % bitWidth
	i := column / bitWidth
	mask := byte(1 << (offset + bit))
	return nm.Data[i]&mask > 0
}

func (nm *NullBitMap) String() string {
	// FIXME: this needs tidying up.
	return fmt.Sprintf("%b", nm.Data)
}
