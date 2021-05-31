package bitmap_test

import (
	"bytes"
	"testing"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding/bitmap"
)

func TestParamBM(t *testing.T) {
	bytes := bytes.NewBuffer([]byte{0x7})
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

func TestCrash(t *testing.T) {
	bytes := bytes.NewBuffer([]byte{0, 1, 0, 128})
	nm, err := bitmap.ReadNullMap(bytes, 30, bitmap.ResultSetRow)
	if err != nil {
		t.Fatal(err)
	}
	if nm.IsNull(24) {
		t.Error("param 24 should not be null")
	}
}
