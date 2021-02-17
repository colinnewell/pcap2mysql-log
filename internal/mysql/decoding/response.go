package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
)

type MySQLtypes struct {
	Catalog     string
	TableAlias  string
	Table       string
	Schema      string
	Column      string
	ColumnAlias string
	FieldInfo   MySQLfieldinfo
}

type MySQLfieldinfo struct {
	LengthOfFixesFields byte
	CharacterSetNumber  uint16
	MaxColumnSize       uint32
	FieldTypes          fieldType
	FieldDetail         fieldDetail
	Decimals            byte
	Unused              uint16
}

// MySQLresponse - dealing with the response.
type MySQLresponse struct {
	Fields []MySQLtypes
	State  readState
}

type readState byte
type fieldType byte
type fieldDetail uint16
type responseType byte

const (
	start readState = iota
	fieldInfo
	data

	MySQLError       responseType = 0xff
	MySQLEOF         responseType = 0xfe
	MySQLOK          responseType = 0
	MySQLLocalInfile responseType = 0xfb
)

//nolint:golint,stylecheck
const (
	DECIMAL     fieldType = 0
	TINY        fieldType = 1
	SHORT       fieldType = 2
	LONG        fieldType = 3
	FLOAT       fieldType = 4
	DOUBLE      fieldType = 5
	NULL        fieldType = 6
	TIMESTAMP   fieldType = 7
	LONGLONG    fieldType = 8
	INT24       fieldType = 9
	DATE        fieldType = 10
	TIME        fieldType = 11
	DATETIME    fieldType = 12
	YEAR        fieldType = 13
	NEWDATE     fieldType = 14
	VARCHAR     fieldType = 15
	BIT         fieldType = 16
	TIMESTAMP2  fieldType = 17
	DATETIME2   fieldType = 18
	TIME2       fieldType = 19
	JSON        fieldType = 245
	NEWDECIMAL  fieldType = 246
	ENUM        fieldType = 247
	SET         fieldType = 248
	TINY_BLOB   fieldType = 249
	MEDIUM_BLOB fieldType = 250
	LONG_BLOB   fieldType = 251
	BLOB        fieldType = 252
	VAR_STRING  fieldType = 253
	STRING      fieldType = 254
	GEOMETRY    fieldType = 255

	DETAIL_NOT_NULL              fieldDetail = 1
	DETAIL_PRIMARY_KEY           fieldDetail = 2
	DETAIL_UNIQUE_KEY            fieldDetail = 4
	DETAIL_MULTIPLE_KEY          fieldDetail = 8
	DETAIL_BLOB                  fieldDetail = 16
	DETAIL_UNSIGNED              fieldDetail = 32
	DETAIL_ZEROFILL_FLAG         fieldDetail = 64
	DETAIL_BINARY_COLLATION      fieldDetail = 128
	DETAIL_ENUM                  fieldDetail = 256
	DETAIL_AUTO_INCREMENT        fieldDetail = 512
	DETAIL_TIMESTAMP             fieldDetail = 1024
	DETAIL_SET                   fieldDetail = 2048
	DETAIL_NO_DEFAULT_VALUE_FLAG fieldDetail = 4096
	DETAIL_ON_UPDATE_NOW_FLAG    fieldDetail = 8192
	DETAIL_PART_KEY_FLAG         fieldDetail = 16384
	DETAIL_NUM_FLAG              fieldDetail = 32768
)

func (d fieldDetail) String() string {
	var b strings.Builder
	for _, flag := range []string{
		"NOT_NULL",
		"PRIMARY_KEY",
		"UNIQUE_KEY",
		"MULTIPLE_KEY",
		"BLOB",
		"UNSIGNED",
		"ZEROFILL_FLAG",
		"BINARY_COLLATION",
		"ENUM",
		"AUTO_INCREMENT",
		"TIMESTAMP",
		"SET",
		"NO_DEFAULT_VALUE_FLAG",
		"ON_UPDATE_NOW_FLAG",
		"PART_KEY_FLAG",
		"NUM_FLAG",
	} {
		if d&1 == 1 {
			if b.Len() > 0 {
				b.WriteString("|")
			}
			b.WriteString(flag)
		}
		d >>= 1
	}

	return b.String()
}

//nolint:funlen,gocyclo
func (f fieldType) String() string {
	switch f {
	case DECIMAL:
		return "MYSQL_TYPE_DECIMAL"
	case TINY:
		return "MYSQL_TYPE_TINY"
	case SHORT:
		return "MYSQL_TYPE_SHORT"
	case LONG:
		return "MYSQL_TYPE_LONG"
	case FLOAT:
		return "MYSQL_TYPE_FLOAT"
	case DOUBLE:
		return "MYSQL_TYPE_DOUBLE"
	case NULL:
		return "MYSQL_TYPE_NULL"
	case TIMESTAMP:
		return "MYSQL_TYPE_TIMESTAMP"
	case LONGLONG:
		return "MYSQL_TYPE_LONGLONG"
	case INT24:
		return "MYSQL_TYPE_INT24"
	case DATE:
		return "MYSQL_TYPE_DATE"
	case TIME:
		return "MYSQL_TYPE_TIME"
	case DATETIME:
		return "MYSQL_TYPE_DATETIME"
	case YEAR:
		return "MYSQL_TYPE_YEAR"
	case NEWDATE:
		return "MYSQL_TYPE_NEWDATE"
	case VARCHAR:
		return "MYSQL_TYPE_VARCHAR"
	case BIT:
		return "MYSQL_TYPE_BIT"
	case TIMESTAMP2:
		return "MYSQL_TYPE_TIMESTAMP2"
	case DATETIME2:
		return "MYSQL_TYPE_DATETIME2"
	case TIME2:
		return "MYSQL_TYPE_TIME2"
	case JSON:
		return "MYSQL_TYPE_JSON"
	case NEWDECIMAL:
		return "MYSQL_TYPE_NEWDECIMAL"
	case ENUM:
		return "MYSQL_TYPE_ENUM"
	case SET:
		return "MYSQL_TYPE_SET"
	case TINY_BLOB:
		return "MYSQL_TYPE_TINY_BLOB"
	case MEDIUM_BLOB:
		return "MYSQL_TYPE_MEDIUM_BLOB"
	case LONG_BLOB:
		return "MYSQL_TYPE_LONG_BLOB"
	case BLOB:
		return "MYSQL_TYPE_BLOB"
	case VAR_STRING:
		return "MYSQL_TYPE_VAR_STRING"
	case STRING:
		return "MYSQL_TYPE_STRING"
	case GEOMETRY:
		return "MYSQL_TYPE_GEOMETRY"
	}
	return "UNRECOGNISED"
}

func (m *MySQLresponse) decodeGreeting(p []byte) error {
	protocol := p[0]
	b := bytes.NewBuffer(p[1:])
	version, err := readNulString(b)
	if err != nil {
		return err
	}
	fmt.Printf("Protocol: %d\nVersion: %s\n", protocol, version)

	// not really interested in all the data here right now.
	// skipping connection id + various other bits.
	//nolint:gomnd
	b.Next(9 + 4)
	capabilityBytes := [4]byte{}
	if n, err := b.Read(capabilityBytes[0:2]); err != nil || n < 2 {
		if err != nil {
			return err
		}
		return fmt.Errorf("only read %d bytes", b.Len())
	}
	collation, err := b.ReadByte()
	if err != nil {
		return err
	}
	if n, err := b.Read(capabilityBytes[2:4]); err != nil || n < 2 {
		if err != nil {
			return err
		}
		return fmt.Errorf("only read %d bytes", b.Len())
	}
	// FIXME: not sure if this is the best way to decode the capability info
	capabilities := binary.LittleEndian.Uint32(capabilityBytes[:])
	fmt.Printf("Collation: %x\nCapabilities: %b - %x\n", collation, capabilities, capabilities)
	return nil
}

//nolint:funlen,gocognit
func (m *MySQLresponse) Write(p []byte) (int, error) {
	// FIXME: check how much data we have
	switch m.State {
	case start:
		if p[packet.PacketNo] == 0 {
			fmt.Printf("Greeting\n%#v\n", p)
			err := m.decodeGreeting(p[packet.HeaderLen:])
			if err != nil {
				return 0, err
			}
			break
		}
		switch responseType(p[packet.HeaderLen]) {
		case MySQLError:
			if len(p) > packet.HeaderLen+3 {
				errorCode := binary.LittleEndian.Uint16(p[packet.HeaderLen+1:])
				if errorCode == packet.InProgress {
					// FIXME: progress
					fmt.Println("Progress")
				} else {
					data := p[packet.HeaderLen+3:]
					var state string
					if data[0] == '#' {
						state = string(data[1:6])
						data = data[6:]
					}
					message := string(data)
					fmt.Printf("Error: #%d: [SQL state %s] %s\n", errorCode, state, message)
				}
			}
		case MySQLEOF:
			// check if it's really an EOF
			fmt.Println("eof state")
		case MySQLOK:
			fmt.Println("ok state")
		case MySQLLocalInfile:
			// check if it's really an EOF
			fmt.Println("In file")
		default:
			fmt.Printf("Expecting: %d fields\n", p[packet.HeaderLen])
			m.State = fieldInfo
			m.Fields = []MySQLtypes{}
		}
	case data:
		if responseType(p[packet.HeaderLen]) == MySQLEOF {
			m.State = start
			break
		}

		fmt.Println("Response Data")
		r := make([]string, len(m.Fields))

		b := bytes.NewBuffer(p[packet.HeaderLen:])

		for i := range r {
			var err error

			r[i], err = readLenEncString(b)

			if err != nil {
				return 0, err
			}
		}

		for i, v := range r {
			fmt.Printf("%s(%s.%s): %s\n", m.Fields[i].ColumnAlias, m.Fields[i].Table, m.Fields[i].Column, v)
		}

	case fieldInfo:
		if responseType(p[packet.HeaderLen]) == MySQLEOF {
			m.State = data
			break
		}

		fmt.Println("Field definition")

		buf := bytes.NewBuffer(p[packet.HeaderLen:])
		field := MySQLtypes{}

		for _, val := range []*string{
			&field.Catalog,
			&field.Schema,
			&field.TableAlias,
			&field.Table,
			&field.ColumnAlias,
			&field.Column,
		} {
			s, err := readLenEncString(buf)

			if err != nil {
				return 0, err
			}

			*val = s
		}

		if err := binary.Read(buf, binary.LittleEndian, &field.FieldInfo); err != nil {
			return 0, err
		}

		m.Fields = append(m.Fields, field)

		fmt.Printf("%+v\n", field)
	default:
		fmt.Printf("Unrecognised packet: %x\n", p[0])
	}

	return len(p), nil
}

func readLenEncString(buf *bytes.Buffer) (string, error) {
	count, err := buf.ReadByte()

	if err != nil {
		return "", err
	}

	s := string(buf.Next(int(count)))

	if len(s) < int(count) {
		return "", fmt.Errorf("only read %d bytes", len(s))
	}

	return s, nil
}

func readNulString(buf *bytes.Buffer) (string, error) {
	vb, err := buf.ReadBytes(0)
	if err != nil {
		return "", err
	}
	return string(vb[:len(vb)-1]), nil
}

// func readFixedString(buf *bytes.Buffer, length int) (string, error) {
// 	b := buf.Next(length)
// 	if len(b) < length {
// 		return "", fmt.Errorf("only read %d bytes", len(b))
// 	}
// 	return string(b), nil
// }
