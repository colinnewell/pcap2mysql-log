package bitmap_test

import (
	"bytes"
	"testing"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding/bitmap"
)

func TestParamBM(t *testing.T) {
	bytes := bytes.NewBuffer([]byte{0xff})
	bm, err := bitmap.ReadNullMap(bytes, 3, bitmap.ExecuteParams)
	if err != nil {
		t.Fatal(err)
	}
	if !bm.IsNull(0) {
		t.Error("param 2 should be null")
	}
	if !bm.IsNull(2) {
		t.Error("param 2 should be null")
	}
}
