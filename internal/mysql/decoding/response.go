package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/orderbynull/lottip/protocol"
)

type mySQLtypes struct {
	Catalog     string
	TableAlias  string
	Table       string
	Schema      string
	Column      string
	ColumnAlias string
	FieldInfo   mySQLfieldinfo
}

type mySQLfieldinfo struct {
	LengthOfFixesFields byte
	CharacterSetNumber  uint16
	MaxColumnSize       uint32
	FieldTypes          byte
	FieldDetail         uint16
	Decimals            byte
	Unused              uint16
}

//MySQLresponse - dealing with the response
type MySQLresponse struct {
	Fields     []mySQLtypes
	InResponse bool
	EOFCount   int
}

func (m *MySQLresponse) Write(p []byte) (int, error) {
	if m.InResponse {
		switch t := protocol.GetPacketType(p); t {
		case protocol.ResponseErr:
			decoded, err := protocol.DecodeErrResponse(p)
			fmt.Printf("%#v: %v\n", decoded, err)
		case protocol.ResponseOk:
			decoded, err := protocol.DecodeOkResponse(p)
			fmt.Printf("%#v: %v\n", decoded, err)
		case 1:
			//assuming this is the data
			fmt.Println("Response Data")
			fmt.Printf("%#v\n", p)
		case 3:
			fmt.Println("Field definition")
			buf := bytes.NewBuffer(p[4:])
			field := mySQLtypes{}

			for _, val := range []*string{
				&field.Catalog,
				&field.Schema,
				&field.TableAlias,
				&field.Table,
				&field.ColumnAlias,
				&field.Column,
			} {
				s, err := readString(buf)

				if err != nil {
					return 0, err
				}

				*val = s
			}

			if err := binary.Read(buf, binary.LittleEndian, &field.FieldInfo); err != nil {
				return 0, err
			}

			m.Fields = append(m.Fields, field)

			fmt.Printf("%#v\n", field)

		case 0xfe:
			fmt.Println("EOF")
			m.EOFCount = m.EOFCount + 1

			if m.EOFCount >= 2 {
				m.InResponse = false
				m.EOFCount = 0
			}
		default:
			fmt.Printf("Unrecognised packet: %x\n", t)
		}
	} else {
		fmt.Printf("Expecting: %d fields\n", p[4])
		m.InResponse = true
	}

	return len(p), nil
}

func readString(buf *bytes.Buffer) (string, error) {
	count, err := buf.ReadByte()

	if err != nil {
		return "", err
	}

	s := string(buf.Next(int(count)))

	if len(s) < int(count) {
		return "", fmt.Errorf("Only read %d bytes", len(s))
	}

	return s, nil
}
