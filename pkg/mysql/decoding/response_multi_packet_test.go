package decoding_test

import (
	"bytes"
	"testing"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/google/go-cmp/cmp"
)

func TestResultsFromExecute(t *testing.T) {
	input := []byte{
		0x01, 0x00, 0x00, 0x01, 0x03, 0x28, 0x00, 0x00, // .....(..
		0x02, 0x03, 0x64, 0x65, 0x66, 0x04, 0x64, 0x65, // ..def.de
		0x6d, 0x6f, 0x05, 0x70, 0x65, 0x65, 0x70, 0x73, // mo.peeps
		0x05, 0x70, 0x65, 0x65, 0x70, 0x73, 0x02, 0x69, // .peeps.i
		0x64, 0x02, 0x69, 0x64, 0x0c, 0x3f, 0x00, 0x0b, // d.id.?..
		0x00, 0x00, 0x00, 0x03, 0x03, 0x42, 0x00, 0x00, // .....B..
		0x00, 0x2c, 0x00, 0x00, 0x03, 0x03, 0x64, 0x65, // .,....de
		0x66, 0x04, 0x64, 0x65, 0x6d, 0x6f, 0x05, 0x70, // f.demo.p
		0x65, 0x65, 0x70, 0x73, 0x05, 0x70, 0x65, 0x65, // eeps.pee
		0x70, 0x73, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x04, // ps.name.
		0x6e, 0x61, 0x6d, 0x65, 0x0c, 0x2d, 0x00, 0x18, // name.-..
		0x01, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x2a, 0x00, 0x00, 0x04, 0x03, 0x64, 0x65, // .*....de
		0x66, 0x04, 0x64, 0x65, 0x6d, 0x6f, 0x05, 0x70, // f.demo.p
		0x65, 0x65, 0x70, 0x73, 0x05, 0x70, 0x65, 0x65, // eeps.pee
		0x70, 0x73, 0x03, 0x61, 0x67, 0x65, 0x03, 0x61, // ps.age.a
		0x67, 0x65, 0x0c, 0x3f, 0x00, 0x0b, 0x00, 0x00, // ge.?....
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // ........
		0x00, 0x00, 0x05, 0xfe, 0x00, 0x00, 0x22, 0x00, // ......".
		0x11, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, // ........
		0x00, 0x00, 0x06, 0x70, 0x65, 0x72, 0x73, 0x6f, // ...perso
		0x6e, 0x21, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, // n!......
		0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, // ........
		0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x32, 0x21, // person2!
		0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x08, 0xfe, // ........
		0x00, 0x00, 0x22, 0x00, // ..".
	}
	expected := []interface{}{
		structure.ResultSetResponse{
			Type: "SQL results",
			Columns: []structure.ColumnInfo{
				{
					Catalog: "def",
					Column:  "id",
					TypeInfo: structure.TypeInfo{
						CharacterSetNumber: 63,
						FieldDetail: structure.DETAIL_NOT_NULL |
							structure.DETAIL_PRIMARY_KEY |
							structure.DETAIL_AUTO_INCREMENT |
							structure.DETAIL_PART_KEY_FLAG,
						FieldTypes:          structure.LONG,
						LengthOfFixedFields: 12,
						MaxColumnSize:       11,
					},
					ColumnAlias: "id",
					TableAlias:  "peeps",
					Table:       "peeps",
					Schema:      "demo",
				},
				{
					Catalog:     "def",
					Column:      "name",
					ColumnAlias: "name",
					TypeInfo: structure.TypeInfo{
						CharacterSetNumber:  45,
						FieldTypes:          253,
						LengthOfFixedFields: 12,
						MaxColumnSize:       280,
					},
					TableAlias: "peeps",
					Table:      "peeps",
					Schema:     "demo",
				},
				{
					Catalog:     "def",
					Column:      "age",
					ColumnAlias: "age",
					TypeInfo: structure.TypeInfo{
						CharacterSetNumber:  63,
						FieldTypes:          3,
						LengthOfFixedFields: 12,
						MaxColumnSize:       11,
					},
					TableAlias: "peeps",
					Table:      "peeps",
					Schema:     "demo",
				},
			},
			Results: [][]interface{}{
				{int32(1), string("person"), int32(33)},
				{int32(2), string("person2"), int32(33)},
			},
		},
	}

	e := testEmitter{Builder: &prevRequestBuilder{
		PreviousRequest: "Execute",
	}}

	testResponsePackets(t, e, input, expected)
}

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
