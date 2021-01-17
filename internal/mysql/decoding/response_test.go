package decoding_test

import (
	"testing"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/decoding"
	"github.com/google/go-cmp/cmp"
)

//nolint:gochecknoglobals
var packets [][]byte

//nolint:gochecknoinits
func init() {
	// from ../pcap2har-go/3306->48508.test
	packets = [][]byte{
		{0x1, 0x0, 0x0, 0x1, 0x3},
		{
			0x28, 0x00, 0x00, 0x02, 0x03, 0x64, 0x65, 0x66, // (....def
			0x04, 0x64, 0x65, 0x6d, 0x6f, 0x05, 0x75, 0x73, // .demo.us
			0x65, 0x72, 0x73, 0x05, 0x75, 0x73, 0x65, 0x72, // ers.user
			0x73, 0x02, 0x69, 0x64, 0x02, 0x69, 0x64, 0x0c, // s.id.id.
			0x3f, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x03, 0x03, // ?.......
			0x42, 0x00, 0x00, 0x00, // B...
		},
		{
			0x2c, 0x00, 0x00, 0x03, 0x03, 0x64, 0x65, 0x66, // ,....def
			0x04, 0x64, 0x65, 0x6d, 0x6f, 0x05, 0x75, 0x73, // .demo.us
			0x65, 0x72, 0x73, 0x05, 0x75, 0x73, 0x65, 0x72, // ers.user
			0x73, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x04, 0x6e, // s.name.n
			0x61, 0x6d, 0x65, 0x0c, 0x08, 0x00, 0xff, 0x00, // ame.....
			0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		},
		{
			0x34, 0x00, 0x00, 0x04, 0x03, 0x64, 0x65, 0x66, // 4....def
			0x04, 0x64, 0x65, 0x6d, 0x6f, 0x05, 0x75, 0x73, // .demo.us
			0x65, 0x72, 0x73, 0x05, 0x75, 0x73, 0x65, 0x72, // ers.user
			0x73, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, // s.userna
			0x6d, 0x65, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, // me.usern
			0x61, 0x6d, 0x65, 0x0c, 0x08, 0x00, 0xff, 0x00, // ame.....
			0x00, 0x00, 0xfd, 0x04, 0x40, 0x00, 0x00, 0x00, // ....@...
		},
		{
			0x05, 0x00, 0x00, 0x05, 0xfe, 0x00, 0x00, 0x22, // ......."
			0x00, // .
		},
		{
			0x10, 0x00, 0x00, 0x06, 0x01, 0x31, 0x04, 0x6e, // .....1.n
			0x61, 0x6d, 0x65, 0x08, 0x75, 0x73, 0x65, 0x72, // ame.user
			0x6e, 0x61, 0x6d, 0x65, // name
		},
		{
			0x05, 0x00, 0x00, 0x07, 0xfe, 0x00, 0x00, 0x22, // ......."
			0x00, // .
		},
	}
}

func TestDecodeReponse(t *testing.T) {
	r := decoding.MySQLresponse{}
	for _, p := range packets {
		_, err := r.Write(p)
		if err != nil {
			t.Fatal(err)
		}
	}

	expected := []decoding.MySQLtypes{
		{
			Catalog:     "def",
			TableAlias:  "users",
			Table:       "users",
			Schema:      "demo",
			Column:      "id",
			ColumnAlias: "id",
			FieldInfo: decoding.MySQLfieldinfo{
				LengthOfFixesFields: 12,
				CharacterSetNumber:  63,
				MaxColumnSize:       11,
				FieldTypes:          decoding.LONG,
				FieldDetail: decoding.DETAIL_NOT_NULL |
					decoding.DETAIL_PRIMARY_KEY |
					decoding.DETAIL_AUTO_INCREMENT |
					decoding.DETAIL_PART_KEY_FLAG,
			},
		},
		{
			Catalog:     "def",
			TableAlias:  "users",
			Table:       "users",
			Schema:      "demo",
			Column:      "name",
			ColumnAlias: "name",
			FieldInfo: decoding.MySQLfieldinfo{
				LengthOfFixesFields: 12,
				CharacterSetNumber:  8,
				MaxColumnSize:       255,
				FieldTypes:          decoding.VAR_STRING,
			},
		},
		{
			Catalog:     "def",
			TableAlias:  "users",
			Table:       "users",
			Schema:      "demo",
			Column:      "username",
			ColumnAlias: "username",
			FieldInfo: decoding.MySQLfieldinfo{
				LengthOfFixesFields: 12,
				CharacterSetNumber:  8,
				MaxColumnSize:       255,
				FieldTypes:          decoding.VAR_STRING,
				FieldDetail:         decoding.DETAIL_UNIQUE_KEY | decoding.DETAIL_PART_KEY_FLAG,
			},
		},
	}
	if diff := cmp.Diff(r.Fields, expected); diff != "" {
		t.Fatalf("Split doesn't match (-got +expected):\n%s\n", diff)
	}
	// FIXME: should check we decode the data in the packets too.
}
