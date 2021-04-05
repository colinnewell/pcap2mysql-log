package decoding_test

import (
	"testing"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
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

type testOneSidedConnectionBuilder struct{}

func (b *testOneSidedConnectionBuilder) AddToConnection(
	request bool, seen []time.Time, typeName string, item interface{}) {
}

func (b *testOneSidedConnectionBuilder) PreviousRequestType() string {
	return ""
}

func (b *testOneSidedConnectionBuilder) JustSeenGreeting() bool {
	return false
}

func (b *testOneSidedConnectionBuilder) ParamsForQuery(query uint32) uint16 {
	return 0
}

type testEmitter struct {
	transmissions []interface{}
	Builder       decoding.ConnectionBuilder
}

func (t *testEmitter) Transmission(typeName string, i interface{}) {
	t.transmissions = append(t.transmissions, i)
}

func (t *testEmitter) ConnectionBuilder() decoding.ConnectionBuilder {
	if t.Builder != nil {
		return t.Builder
	}
	return &testOneSidedConnectionBuilder{}
}

func TestDecodeReponse(t *testing.T) {
	e := testEmitter{}
	r := decoding.ResponseDecoder{Emit: &e}
	for _, p := range packets {
		_, err := r.Write(p)
		if err != nil {
			t.Fatal(err)
		}
	}

	r.FlushResponse()

	expected := []interface{}{
		structure.ResultSetResponse{
			Type: "SQL results",
			Columns: []structure.ColumnInfo{
				{
					Catalog:     "def",
					TableAlias:  "users",
					Table:       "users",
					Schema:      "demo",
					Column:      "id",
					ColumnAlias: "id",
					TypeInfo: structure.TypeInfo{
						LengthOfFixedFields: 12,
						CharacterSetNumber:  63,
						MaxColumnSize:       11,
						FieldTypes:          structure.LONG,
						FieldDetail: structure.DETAIL_NOT_NULL |
							structure.DETAIL_PRIMARY_KEY |
							structure.DETAIL_AUTO_INCREMENT |
							structure.DETAIL_PART_KEY_FLAG,
					},
				},
				{
					Catalog:     "def",
					TableAlias:  "users",
					Table:       "users",
					Schema:      "demo",
					Column:      "name",
					ColumnAlias: "name",
					TypeInfo: structure.TypeInfo{
						LengthOfFixedFields: 12,
						CharacterSetNumber:  8,
						MaxColumnSize:       255,
						FieldTypes:          structure.VAR_STRING,
					},
				},
				{
					Catalog:     "def",
					TableAlias:  "users",
					Table:       "users",
					Schema:      "demo",
					Column:      "username",
					ColumnAlias: "username",
					TypeInfo: structure.TypeInfo{
						LengthOfFixedFields: 12,
						CharacterSetNumber:  8,
						MaxColumnSize:       255,
						FieldTypes:          structure.VAR_STRING,
						FieldDetail:         structure.DETAIL_UNIQUE_KEY | structure.DETAIL_PART_KEY_FLAG,
					},
				},
			},
			Results: [][]string{{"1", "name", "username"}},
		},
	}

	if diff := cmp.Diff(e.transmissions, expected); diff != "" {
		t.Fatalf("Split doesn't match (-got +expected):\n%s\n", diff)
	}
}

func TestOKResponse(t *testing.T) {
	input := []byte{
		0x07, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x00, 0x00, 0x00,
	}

	expected := []interface{}{
		structure.OKResponse{
			AffectedRows: 1,
			LastInsertID: 2,
			ServerStatus: 2,
			Type:         "OK",
		},
	}

	testResponse(t, input, expected)
}

func TestOKResponseOnLogin(t *testing.T) {
	input := []byte{
		0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, // ........
		0x40, 0x00, 0x00, 0x00, 0x07, 0x01, 0x05, 0x04, // @.......
		0x64, 0x65, 0x6d, 0x6f, // demo
	}
	// TODO: read more of the trailing info.
	expected := []interface{}{
		structure.OKResponse{
			AffectedRows: 0,
			LastInsertID: 0,
			ServerStatus: 0x4002,
			Type:         "OK",
		},
	}
	testResponse(t, input, expected)
}

func TestDecodeExecuteOK(t *testing.T) {
	input := []byte{
		0x07, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x02, // ........
		0x00, 0x00, 0x00, // ...
	}
	expected := []interface{}{
		structure.OKResponse{
			AffectedRows: 1,
			LastInsertID: 1,
			ServerStatus: 2,
			Type:         "OK",
		},
	}
	e := testEmitter{
		Builder: &prevRequestBuilder{PreviousRequest: "Execute"},
	}
	testResponseEx(t, e, input, expected)
}

type prevRequestBuilder struct {
	PreviousRequest  string
	PreviousRequests []string
	Params           uint16
}

func (b *prevRequestBuilder) AddToConnection(
	request bool, seen []time.Time, typeName string, item interface{}) {
}

func (b *prevRequestBuilder) PreviousRequestType() string {
	if len(b.PreviousRequests) > 0 {
		req := b.PreviousRequests[0]
		b.PreviousRequests = b.PreviousRequests[1:]
		return req
	}

	return b.PreviousRequest
}

func (b *prevRequestBuilder) JustSeenGreeting() bool {
	return false
}

func (b *prevRequestBuilder) ParamsForQuery(query uint32) uint16 {
	return b.Params
}

func testResponse(t *testing.T, input []byte, expected []interface{}) {
	t.Helper()

	testResponseEx(t, testEmitter{}, input, expected)
}

func testResponseEx(t *testing.T, e testEmitter, input []byte, expected []interface{}) {
	t.Helper()

	r := decoding.ResponseDecoder{Emit: &e}
	if _, err := r.Write(input); err != nil {
		t.Fatal(err)
	}
	r.FlushResponse()

	if diff := cmp.Diff(e.transmissions, expected); diff != "" {
		t.Fatalf("Output doesn't match (-got +expected):\n%s\n", diff)
	}
}
