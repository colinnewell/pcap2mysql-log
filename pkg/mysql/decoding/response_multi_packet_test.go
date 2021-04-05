package decoding_test

import (
	"bytes"
	"testing"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/google/go-cmp/cmp"
)

func TestPrepareOKResponse(t *testing.T) {
	input := []byte{
		// OK from prepare
		0x0c, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, // ........
		0x17, 0x00, 0x00, 0x02, 0x03, 0x64, 0x65, 0x66, // .....def
		0x00, 0x00, 0x00, 0x01, 0x3f, 0x00, 0x0c, 0x3f, // ....?..?
		0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x80, 0x00, // ........
		0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x03, 0x03, // ........
		0x64, 0x65, 0x66, 0x00, 0x00, 0x00, 0x01, 0x3f, // def....?
		0x00, 0x0c, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, // ..?.....
		0xfd, 0x80, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, // ........
		0x00, 0x04, 0x03, 0x64, 0x65, 0x66, 0x00, 0x00, // ...def..
		0x00, 0x01, 0x3f, 0x00, 0x0c, 0x3f, 0x00, 0x00, // ..?..?..
		0x00, 0x00, 0x00, 0xfd, 0x80, 0x00, 0x00, 0x00, // ........
		0x00, 0x05, 0x00, 0x00, 0x05, 0xfe, 0x00, 0x00, // ........
		0x03, 0x00, // ..
		// OK from Execute
		0x07, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x02, // ........
		0x00, 0x00, 0x00, // ...
	}

	expected := []interface{}{
		structure.PrepareOKResponse{
			Type:        "PREPARE_OK",
			StatementID: 1,
			NumParams:   3,
			Params: []structure.ColumnInfo{
				{
					Catalog:     "def",
					ColumnAlias: "?",
					TypeInfo: structure.TypeInfo{
						LengthOfFixedFields: 12,
						CharacterSetNumber:  63,
						FieldTypes:          253,
						FieldDetail:         128,
					},
				},
				{
					Catalog:     "def",
					ColumnAlias: "?",
					TypeInfo: structure.TypeInfo{
						LengthOfFixedFields: 12,
						CharacterSetNumber:  63,
						FieldTypes:          253,
						FieldDetail:         128,
					},
				},
				{
					Catalog:     "def",
					ColumnAlias: "?",
					TypeInfo: structure.TypeInfo{
						LengthOfFixedFields: 12,
						CharacterSetNumber:  63,
						FieldTypes:          253,
						FieldDetail:         128,
					},
				},
			},
		},
		structure.OKResponse{
			AffectedRows: 1,
			LastInsertID: 1,
			ServerStatus: 2,
			Type:         "OK",
		},
	}

	e := testEmitter{Builder: &prevRequestBuilder{
		PreviousRequests: []string{"Prepare", "Execute"},
	}}

	testResponsePackets(t, e, input, expected)
}

func testResponsePackets(t *testing.T, e testEmitter, input []byte, expected []interface{}) {
	t.Helper()

	r := decoding.ResponseDecoder{Emit: &e}
	buf := bytes.NewBuffer(input)
	if _, err := packet.Copy(buf, &r); err != nil {
		t.Fatal(err)
	}
	r.FlushResponse()

	if diff := cmp.Diff(e.transmissions, expected); diff != "" {
		t.Fatalf("Output doesn't match (-got +expected):\n%s\n", diff)
	}
}
