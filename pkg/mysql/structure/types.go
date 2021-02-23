package structure

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
)

type ConversationAddress struct {
	IP, Port gopacket.Flow
}

func (c ConversationAddress) MarshalJSON() ([]byte, error) {
	src, dest := c.IP.Endpoints()
	sPort, dPort := c.Port.Endpoints()

	return json.Marshal(fmt.Sprintf("%s:%s - %s:%s", src, sPort, dest, dPort))
}

type Conversation struct {
	Address ConversationAddress
	Items   []Transmission
}

type Transmission struct {
	Data interface{}
	Seen []time.Time
}

type Request struct {
	Type  string `json:"Type"`
	Query string `json:"Query,omitempty"`
}

type Response struct {
	Type    string      `json:"Type"`
	Fields  []FieldInfo `json:"Fields,omitempty"`
	Results [][]string  `json:"Results,omitempty"`
}

type OKResponse struct {
	AffectedRows uint64
	LastInsertID uint64
	ServerStatus uint16
	WarningCount uint16
	// FIXME: deal with session tracking
	Type string `json:"Type"`
	Info string
}

type ErrorResponse struct {
	Code    uint16
	Type    string
	State   string `json:"State,omitempty"`
	Message string
}

type FieldInfo struct {
	Catalog     string
	TableAlias  string
	Table       string
	Schema      string
	Column      string
	ColumnAlias string
	TypeInfo    TypeInfo
}

type TypeInfo struct {
	LengthOfFixedFields byte
	CharacterSetNumber  uint16
	MaxColumnSize       uint32
	FieldTypes          FieldType
	FieldDetail         FieldDetail
	Decimals            byte
	Unused              uint16
}

type Greeting struct {
	Capabilities uint32
	Collation    byte
	Protocol     byte
	Version      string
	Type         string
}

type FieldType byte
type FieldDetail uint16
type ResponseType byte

const (
	MySQLError       ResponseType = 0xff
	MySQLEOF         ResponseType = 0xfe
	MySQLOK          ResponseType = 0
	MySQLLocalInfile ResponseType = 0xfb
)

//nolint:golint,stylecheck
const (
	DECIMAL     FieldType = 0
	TINY        FieldType = 1
	SHORT       FieldType = 2
	LONG        FieldType = 3
	FLOAT       FieldType = 4
	DOUBLE      FieldType = 5
	NULL        FieldType = 6
	TIMESTAMP   FieldType = 7
	LONGLONG    FieldType = 8
	INT24       FieldType = 9
	DATE        FieldType = 10
	TIME        FieldType = 11
	DATETIME    FieldType = 12
	YEAR        FieldType = 13
	NEWDATE     FieldType = 14
	VARCHAR     FieldType = 15
	BIT         FieldType = 16
	TIMESTAMP2  FieldType = 17
	DATETIME2   FieldType = 18
	TIME2       FieldType = 19
	JSON        FieldType = 245
	NEWDECIMAL  FieldType = 246
	ENUM        FieldType = 247
	SET         FieldType = 248
	TINY_BLOB   FieldType = 249
	MEDIUM_BLOB FieldType = 250
	LONG_BLOB   FieldType = 251
	BLOB        FieldType = 252
	VAR_STRING  FieldType = 253
	STRING      FieldType = 254
	GEOMETRY    FieldType = 255

	DETAIL_NOT_NULL              FieldDetail = 1
	DETAIL_PRIMARY_KEY           FieldDetail = 2
	DETAIL_UNIQUE_KEY            FieldDetail = 4
	DETAIL_MULTIPLE_KEY          FieldDetail = 8
	DETAIL_BLOB                  FieldDetail = 16
	DETAIL_UNSIGNED              FieldDetail = 32
	DETAIL_ZEROFILL_FLAG         FieldDetail = 64
	DETAIL_BINARY_COLLATION      FieldDetail = 128
	DETAIL_ENUM                  FieldDetail = 256
	DETAIL_AUTO_INCREMENT        FieldDetail = 512
	DETAIL_TIMESTAMP             FieldDetail = 1024
	DETAIL_SET                   FieldDetail = 2048
	DETAIL_NO_DEFAULT_VALUE_FLAG FieldDetail = 4096
	DETAIL_ON_UPDATE_NOW_FLAG    FieldDetail = 8192
	DETAIL_PART_KEY_FLAG         FieldDetail = 16384
	DETAIL_NUM_FLAG              FieldDetail = 32768
)

func (d FieldDetail) String() string {
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
func (f FieldType) String() string {
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
