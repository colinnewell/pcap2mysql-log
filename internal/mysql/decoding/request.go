package decoding

import (
	"fmt"

	"github.com/orderbynull/lottip/protocol"
)

type MySQLRequest struct {
}

func (m *MySQLRequest) Write(p []byte) (int, error) {
	switch t := protocol.GetPacketType(p); t {
	case protocol.ComStmtPrepare:
		fmt.Println("Prepare")
	case protocol.ComQuery:
		decoded, err := protocol.DecodeQueryRequest(p)
		if err != nil {
			fmt.Printf("%v: %#v\n", err, p)
		} else {
			fmt.Printf("%#v\n", decoded)
		}
	case protocol.ComQuit:
		fmt.Println("quit")
		fmt.Printf("%#v\n", p)
	case protocol.ResponseErr:
		decoded, err := protocol.DecodeErrResponse(p)
		fmt.Printf("%#v: %v\n", decoded, err)
	case protocol.ResponseOk:
		decoded, err := protocol.DecodeOkResponse(p)
		fmt.Printf("%#v: %v\n", decoded, err)
	case 0x04:
		fmt.Println("Field list")
		fmt.Printf("%#v\n", p)
		// should expect a bunch of fields followed by an EOF
		// specifies number of fields to expect
	case 0xfe:
		fmt.Println("EOF")
	default:
		fmt.Printf("Unrecognised packet: %x\n", t)
	}
	return len(p), nil
}
