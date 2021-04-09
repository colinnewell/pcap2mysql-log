package bitmap

import (
	"bytes"

	"github.com/pkg/errors"
)

var errReadPastEnd = errors.New("attempt to read past end of bitmap")

const ResultSetRow = 9
const ExecuteParams = 7

type NullBitMap struct {
	bm     []byte
	width  int
	params int
}

func ReadNullMap(buf *bytes.Buffer, paramCount int, width int) (*NullBitMap, error) {
	neededBytes := (paramCount + width) / 8
	data := make([]byte, neededBytes)

	if _, err := buf.Read(data); err != nil {
		return nil, errors.Wrap(err, "failed to read nullmap")
	}

	return &NullBitMap{bm: data, params: paramCount, width: width}, nil
}

func (nm *NullBitMap) IsNull(column int) bool {
	// expecting column to start at 0
	if column >= nm.params {
		panic(errReadPastEnd)
	}

	var bitWidth, offset int

	if nm.width == ExecuteParams {
		bitWidth = 8
		offset = 0
		// simple figure out byte then bit
	} else {
		bitWidth = 6
		offset = 2
		// data starts at bit 3 (what are the first 2 ?)
	}

	bit := column % bitWidth
	i := offset + (column / bitWidth)
	mask := byte(1 << bit)
	return nm.bm[i]&mask > 0
}
