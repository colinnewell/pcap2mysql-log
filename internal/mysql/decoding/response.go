package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
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
	FieldTypes          fieldType
	FieldDetail         fieldDetail
	Decimals            byte
	Unused              uint16
}

//MySQLresponse - dealing with the response
type MySQLresponse struct {
	Fields []mySQLtypes
	State  readState
}

type readState byte
type fieldType byte
type fieldDetail uint16

const (
	start readState = iota
	fieldInfo
	data

	DECIMAL     fieldType = 0
	TINY                  = 1
	SHORT                 = 2
	LONG                  = 3
	FLOAT                 = 4
	DOUBLE                = 5
	NULL                  = 6
	TIMESTAMP             = 7
	LONGLONG              = 8
	INT24                 = 9
	DATE                  = 10
	TIME                  = 11
	DATETIME              = 12
	YEAR                  = 13
	NEWDATE               = 14
	VARCHAR               = 15
	BIT                   = 16
	TIMESTAMP2            = 17
	DATETIME2             = 18
	TIME2                 = 19
	JSON                  = 245
	NEWDECIMAL            = 246
	ENUM                  = 247
	SET                   = 248
	TINY_BLOB             = 249
	MEDIUM_BLOB           = 250
	LONG_BLOB             = 251
	BLOB                  = 252
	VAR_STRING            = 253
	STRING                = 254
	GEOMETRY              = 255

	DETAIL_NOT_NULL              fieldDetail = 1
	DETAIL_PRIMARY_KEY                       = 2
	DETAIL_UNIQUE_KEY                        = 4
	DETAIL_MULTIPLE_KEY                      = 8
	DETAIL_BLOB                              = 16
	DETAIL_UNSIGNED                          = 32
	DETAIL_ZEROFILL_FLAG                     = 64
	DETAIL_BINARY_COLLATION                  = 128
	DETAIL_ENUM                              = 256
	DETAIL_AUTO_INCREMENT                    = 512
	DETAIL_TIMESTAMP                         = 1024
	DETAIL_SET                               = 2048
	DETAIL_NO_DEFAULT_VALUE_FLAG             = 4096
	DETAIL_ON_UPDATE_NOW_FLAG                = 8192
	DETAIL_NUM_FLAG                          = 32768
)

func (d fieldDetail) String() string {
	var b strings.Builder
	if d&32768 == 32768 {
		b.WriteString("NUM_FLAG")
	}
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
	} {
		if d&1 == 1 {
			if b.Len() > 0 {
				b.WriteString("|")
			}
			b.WriteString(flag)
		}
		d = d >> 1
	}

	return b.String()
}

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
			m.Fields = []mySQLtypes{}
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
