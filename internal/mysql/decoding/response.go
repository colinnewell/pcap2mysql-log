package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
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

//MySQLresponse - dealing with the response.
type MySQLresponse struct {
	Fields []MySQLtypes
	State  readState
}

type readState byte
type fieldType byte
type fieldDetail uint16

//nolint:golint
const (
	start readState = iota
	fieldInfo
	data

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
	case 0:
		return "MYSQL_TYPE_DECIMAL"
	case 1:
		return "MYSQL_TYPE_TINY"
	case 2:
		return "MYSQL_TYPE_SHORT"
	case 3:
		return "MYSQL_TYPE_LONG"
	case 4:
		return "MYSQL_TYPE_FLOAT"
	case 5:
		return "MYSQL_TYPE_DOUBLE"
	case 6:
		return "MYSQL_TYPE_NULL"
	case 7:
		return "MYSQL_TYPE_TIMESTAMP"
	case 8:
		return "MYSQL_TYPE_LONGLONG"
	case 9:
		return "MYSQL_TYPE_INT24"
	case 10:
		return "MYSQL_TYPE_DATE"
	case 11:
		return "MYSQL_TYPE_TIME"
	case 12:
		return "MYSQL_TYPE_DATETIME"
	case 13:
		return "MYSQL_TYPE_YEAR"
	case 14:
		return "MYSQL_TYPE_NEWDATE"
	case 15:
		return "MYSQL_TYPE_VARCHAR"
	case 16:
		return "MYSQL_TYPE_BIT"
	case 17:
		return "MYSQL_TYPE_TIMESTAMP2"
	case 18:
		return "MYSQL_TYPE_DATETIME2"
	case 19:
		return "MYSQL_TYPE_TIME2"
	case 245:
		return "MYSQL_TYPE_JSON"
	case 246:
		return "MYSQL_TYPE_NEWDECIMAL"
	case 247:
		return "MYSQL_TYPE_ENUM"
	case 248:
		return "MYSQL_TYPE_SET"
	case 249:
		return "MYSQL_TYPE_TINY_BLOB"
	case 250:
		return "MYSQL_TYPE_MEDIUM_BLOB"
	case 251:
		return "MYSQL_TYPE_LONG_BLOB"
	case 252:
		return "MYSQL_TYPE_BLOB"
	case 253:
		return "MYSQL_TYPE_VAR_STRING"
	case 254:
		return "MYSQL_TYPE_STRING"
	case 255:
		return "MYSQL_TYPE_GEOMETRY"
	}
	return "UNRECOGNISED"
}

//nolint:funlen
func (m *MySQLresponse) Write(p []byte) (int, error) {
	switch m.State {
	case start:
		fmt.Printf("%#v\n", p[0:])
		switch p[4] {
		//err
		case 0xff:
			fmt.Println("error state")
		//eof
		case 0xfe:
			fmt.Println("eof state")
		//ok
		case 0x00:
			fmt.Println("ok state")
		//local in-file
		case 0xfb:
			fmt.Println("In file")
		default:
			fmt.Printf("Expecting: %d fields\n", p[4])
			m.State = fieldInfo
			m.Fields = []MySQLtypes{}
		}
	case data:
		if p[4] == 0xfe {
			m.State = start
			break
		}

		fmt.Println("Response Data")
		r := make([]string, len(m.Fields))

		b := bytes.NewBuffer(p[4:])

		for i := range r {
			var err error

			r[i], err = readString(b)

			if err != nil {
				return 0, err
			}
		}

		for i, v := range r {
			fmt.Printf("%s(%s.%s): %s\n", m.Fields[i].ColumnAlias, m.Fields[i].Table, m.Fields[i].Column, v)
		}

	case fieldInfo:
		if p[4] == 0xfe {
			m.State = data
			break
		}

		fmt.Println("Field definition")

		buf := bytes.NewBuffer(p[4:])
		field := MySQLtypes{}

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

		fmt.Printf("%+v\n", field)
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
