package bitmap

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
)

var errReadPastEnd = errors.New("attempt to read past end of bitmap")

const ResultSetRow = 9
const ExecuteParams = 7
const byteWidth = 8

type NullBitMap struct {
	Data   []byte
	Width  int
	Params int
}

func New(data []byte, params int, width int) *NullBitMap {
	return &NullBitMap{Data: data, Params: params, Width: width}
}

func ReadNullMap(buf io.Reader, paramCount int, width int) (*NullBitMap, error) {
	neededBytes := (paramCount + width) / byteWidth
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

	if nm.Width == ResultSetRow {
		column += 2
	}

	bit := column % byteWidth
	i := column / byteWidth
	mask := byte(1 << bit)
	return nm.Data[i]&mask > 0
}

func (nm *NullBitMap) String() string {
	// FIXME: this needs tidying up.
	return fmt.Sprintf("%b", nm.Data)
}
