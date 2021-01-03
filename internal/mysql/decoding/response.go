package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	Fields []mySQLtypes
	State  readState
}

type readState byte

const (
	start readState = iota
	fieldInfo
	data
)

func (m *MySQLresponse) Write(p []byte) (int, error) {
	switch m.State {
	case start:
		fmt.Printf("Expecting: %d fields\n", p[4])
		m.State = fieldInfo
	case data:
		if p[4] == 0xfe {
			m.State = start
			break
		}

		fmt.Println("Response Data")
		fmt.Printf("%#v\n", p)
	case fieldInfo:
		if p[4] == 0xfe {
			m.State = data
			break
		}

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
	default:
		fmt.Printf("Unrecognised packet: %x\n", p[0])
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
