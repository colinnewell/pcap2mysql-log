package decoding_test

import (
	"testing"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding/bitmap"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
)

func TestDecodeRequest(t *testing.T) {
	//nolint:misspell
	input := []byte{
		0x46, 0x00, 0x00, 0x00, 0x03, 0x53, 0x45, 0x4c, // F....SEL
		0x45, 0x43, 0x54, 0x20, 0x69, 0x64, 0x2c, 0x20, // ECT id,
		0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, // password
		0x2c, 0x20, 0x75, 0x32, 0x66, 0x2c, 0x20, 0x74, // , u2f, t
		0x6f, 0x74, 0x70, 0x20, 0x46, 0x52, 0x4f, 0x4d, // otp FROM
		0x20, 0x75, 0x73, 0x65, 0x72, 0x73, 0x20, 0x57, //  users W
		0x48, 0x45, 0x52, 0x45, 0x20, 0x75, 0x73, 0x65, // HERE use
		0x72, 0x6e, 0x61, 0x6d, 0x65, 0x20, 0x3d, 0x20, // rname =
		0x27, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, // 'usernam
		0x65, 0x27, // e'
	}

	expected := []interface{}{
		structure.Request{
			Type:  "Query",
			Query: "SELECT id, password, u2f, totp FROM users WHERE username = 'username'",
		},
	}

	testRequestDecode(t, input, expected)
}

func TestDecodeExecute(t *testing.T) {
	input := []byte{
		0x15, 0x00, 0x00, 0x00, 0x17, 0x17, 0x00, 0x00, // ........
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, // ........
		0xfe, 0x00, 0x06, 0x4a, 0x6f, 0x62, 0x62, 0x62, // ...Jobbb
		0x62, // b
	}
	expected := []interface{}{
		structure.ExecuteRequest{
			Type:           "Execute",
			StatementID:    23,
			IterationCount: 1,
			NullMap: bitmap.New(
				[]uint8{0}, 1, bitmap.ExecuteParams,
			),
			Params: []interface{}{"Jobbbb"},
		},
	}
	e := testEmitter{Builder: &prevRequestBuilder{Params: 1}}
	testRequestDecodeEx(t, e, input, expected)
}

func TestDecodeExecuteNilParam(t *testing.T) {
	input := []byte{
		0x25, 0x00, 0x00, 0x00, 0x17, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0xfe, 0x00,
		0x06, 0x00, 0xfe, 0x00, 0x07, 0x70, 0x65, 0x72, 0x73,
		0x6f, 0x6e, 0x34, 0x0a, 0x4c, 0x69, 0x66, 0x65, 0x20,
		0x73, 0x74, 0x6f, 0x72, 0x79,
	}
	expected := []interface{}{
		structure.ExecuteRequest{
			Type:           "Execute",
			StatementID:    1,
			IterationCount: 1,
			NullMap: bitmap.New(
				[]uint8{2}, 3, bitmap.ExecuteParams,
			),
			Params: []interface{}{"person4", nil, "Life story"},
		},
	}
	e := testEmitter{Builder: &prevRequestBuilder{Params: 3}}
	testRequestDecodeEx(t, e, input, expected)
}

func TestDecodeLogin(t *testing.T) {
	input := []byte{
		0x1f, 0x01, 0x00, 0x01, 0x8f, 0xa2, 0x9e, 0x00, // ........
		0x00, 0x00, 0x00, 0x40, 0x08, 0x00, 0x00, 0x00, // ...@....
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x73, 0x69, 0x74, 0x65, // ....site
		0x00, 0x14, 0x84, 0x20, 0x6b, 0x76, 0xdb, 0xd1, // ... kv..
		0x45, 0xb1, 0x07, 0xfd, 0x8f, 0x72, 0xba, 0xd7, // E....r..
		0x24, 0xb9, 0x96, 0x00, 0x78, 0x22, 0x64, 0x65, // $...x"de
		0x6d, 0x6f, 0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c, // mo.mysql
		0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, // _native_
		0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, // password
		0x00, 0xc9, 0x03, 0x5f, 0x6f, 0x73, 0x05, 0x4c, // ..._os.L
		0x69, 0x6e, 0x75, 0x78, 0x0c, 0x5f, 0x63, 0x6c, // inux._cl
		0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, // ient_nam
		0x65, 0x0a, 0x6c, 0x69, 0x62, 0x6d, 0x61, 0x72, // e.libmar
		0x69, 0x61, 0x64, 0x62, 0x04, 0x5f, 0x70, 0x69, // iadb._pi
		0x64, 0x01, 0x37, 0x0f, 0x5f, 0x63, 0x6c, 0x69, // d.7._cli
		0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, // ent_vers
		0x69, 0x6f, 0x6e, 0x05, 0x33, 0x2e, 0x31, 0x2e, // ion.3.1.
		0x37, 0x09, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, // 7._platf
		0x6f, 0x72, 0x6d, 0x06, 0x78, 0x38, 0x36, 0x5f, // orm.x86_
		0x36, 0x34, 0x0c, 0x70, 0x72, 0x6f, 0x67, 0x72, // 64.progr
		0x61, 0x6d, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x58, // am_nameX
		0x73, 0x74, 0x61, 0x72, 0x6d, 0x61, 0x6e, 0x20, // starman
		0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x20, 0x2d, // worker -
		0x4d, 0x43, 0x61, 0x72, 0x70, 0x3a, 0x3a, 0x41, // MCarp::A
		0x6c, 0x77, 0x61, 0x79, 0x73, 0x20, 0x2d, 0x49, // lways -I
		0x20, 0x2f, 0x6f, 0x70, 0x74, 0x2f, 0x69, 0x6e, //  /opt/in
		0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2d, 0x64, // secure-d
		0x65, 0x6d, 0x6f, 0x2f, 0x6c, 0x69, 0x62, 0x2f, // emo/lib/
		0x20, 0x2f, 0x6f, 0x70, 0x74, 0x2f, 0x69, 0x6e, //  /opt/in
		0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2d, 0x64, // secure-d
		0x65, 0x6d, 0x6f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, // emo/bin/
		0x61, 0x70, 0x70, 0x2e, 0x70, 0x73, 0x67, 0x69, // app.psgi
		0x0c, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, // ._server
		0x5f, 0x68, 0x6f, 0x73, 0x74, 0x05, 0x6d, 0x79, // _host.my
		0x73, 0x71, 0x6c, // sql
	}
	expected := []interface{}{
		structure.LoginRequest{
			Type:               "Login",
			ClientCapabilities: 10396303,
			Collation:          8,
			MaxPacketSize:      1073741824,
			Username:           "site",
		},
	}
	testRequestDecode(t, input, expected)
}

func TestDecodeExecWithParams(t *testing.T) {
	input := []byte{
		31, 0, 0, 0, 23, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 254, 0, 8, 0, 6, 112,
		101, 114, 115, 111, 110, 33, 0, 0, 0, 0, 0, 0, 0,
	}
	expected := []interface{}{
		structure.ExecuteRequest{
			Type:           "Execute",
			StatementID:    1,
			IterationCount: 1,
			NullMap: bitmap.New(
				[]uint8{0}, 2, bitmap.ExecuteParams,
			),
			Params: []interface{}{"person", int64(33)},
			// FIXME: should have a second param too
		},
	}
	e := testEmitter{Builder: &prevRequestBuilder{Params: 2}}
	testRequestDecodeEx(t, e, input, expected)
}

func testRequestDecode(t *testing.T, input []byte, expected []interface{}) {
	t.Helper()

	e := testEmitter{}
	testRequestDecodeEx(t, e, input, expected)
}

func testRequestDecodeEx(t *testing.T, e testEmitter, input []byte, expected []interface{}) {
	t.Helper()

	r := decoding.RequestDecoder{Emit: &e}
	_, err := r.Write(input)
	if err != nil {
		type stackTracer interface {
			StackTrace() errors.StackTrace
		}

		withStack, ok := err.(stackTracer)
		if !ok {
			t.Fatal(err)
		}

		st := withStack.StackTrace()

		t.Fatal(st, err)
	}

	if diff := cmp.Diff(e.transmissions, expected); diff != "" {
		t.Fatalf("Transmission does not match (-got +expected):\n%s\n", diff)
	}
}
