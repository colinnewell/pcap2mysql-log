package structure

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding/bitmap"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/google/gopacket"
)

type ConnectionAddress struct {
	IP, Port gopacket.Flow
}

func (c ConnectionAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c ConnectionAddress) String() string {
	src, dest := c.IP.Endpoints()
	sPort, dPort := c.Port.Endpoints()

	return fmt.Sprintf("%s:%s - %s:%s", src, sPort, dest, dPort)
}

type Connection struct {
	Address ConnectionAddress
	Items   []Transmission
}

func (c Connection) FirstSeen() time.Time {
	if len(c.Items) > 0 && len(c.Items[0].Seen) > 0 {
		return c.Items[0].Seen[0]
	}
	return time.Time{}
}

type Transmission struct {
	Data interface{}
	Seen []time.Time
}

type DecodeError struct {
	CompressionOn       bool
	DecodeError         error
	DecodeErrorString   string
	Direction           string
	JustSeenGreeting    bool `json:"JustSeenGreeting,omitempty"`
	Packet              *packet.Packet
	PreviousRequestType string `json:"PreviousRequestType,omitempty"`
}

type Request struct {
	CorePacket
	Query string `json:"Query,omitempty"`
}

type ExecuteRequest struct {
	CorePacket
	StatementID    uint32
	Flags          uint8
	IterationCount uint32
	// FIXME: ought to think about how to express this in the output.
	NullMap *bitmap.NullBitMap
	Params  []interface{}
}

type LoginRequest struct {
	CorePacket
	ClientCapabilities   ClientCapabilities
	Collation            byte
	ExtendedCapabilities uint32
	MaxPacketSize        uint32
	Username             string
}

type Response struct {
	CorePacket
}

type ResultSetResponse struct {
	CorePacket
	Columns []ColumnInfo    `json:"Columns"`
	Results [][]interface{} `json:"Results"`
}

type ClientCapabilities uint32

func (c ClientCapabilities) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c ClientCapabilities) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%d: ", c))
	startLen := b.Len()
	for _, flag := range []string{
		"CLIENT_MYSQL",
		"FOUND_ROWS",
		"LONG_FLAG", // referenced in wireshark
		"CONNECT_WITH_DB",
		"NO SCHEMA",
		"COMPRESS",
		"ODBC",
		"LOCAL_FILES",
		"IGNORE_SPACE",
		"CLIENT_PROTOCOL_41",
		"CLIENT_INTERACTIVE",
		"SSL",
		"TRANSACTIONS",
		"SECURE_CONNECTION",
		"UNKNOWN",
		"UNKNOWN",
		"MULTI_STATEMENTS",
		"MULTI_RESULTS",
		"PS_MULTI_RESULTS",
		"PLUGIN_AUTH",
		"CONNECT_ATTRS",
		"PLUGIN_AUTH_LENENC_CLIENT_DATA",
		"UNKNOWN",
		"CLIENT_SESSION_TRACK",
		"CLIENT_DEPRECATE_EOF",
		"UNKNOWN",
		"CLIENT_ZSTD_COMPRESSION_ALGORITHM",
		"UNKNOWN",
		"UNKNOWN",
		"CLIENT_CAPABILITY_EXTENSION",
	} {
		if c&1 == 1 {
			if b.Len() > startLen {
				b.WriteString("|")
			}
			b.WriteString(flag)
		}
		c >>= 1
	}

	return b.String()
}

// Extended capabilities?
// MARIADB_CLIENT_PROGRESS	1 << 32	Client support progress indicator (since 10.2)
// MARIADB_CLIENT_COM_MULTI	1 << 33	Permit COM_MULTI protocol
// MARIADB_CLIENT_STMT_BULK_OPERATIONS	1 << 34	Permit bulk insert
// MARIADB_CLIENT_EXTENDED_TYPE_INFO	1 << 35	add extended metadata information

type StatusFlags uint16

func (f StatusFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%x: %s", uint16(f), f.String()))
}

func (f StatusFlags) String() string {
	var b strings.Builder
	for _, flag := range []string{
		"SERVER_STATUS_IN_TRANS",
		"SERVER_STATUS_AUTOCOMMIT",
		"Unknown!", // haven't spotted this in the docs yet.
		"SERVER_MORE_RESULTS_EXISTS",
		"SERVER_STATUS_NO_GOOD_INDEX_USED",
		"SERVER_STATUS_NO_INDEX_USED",
		"SERVER_STATUS_CURSOR_EXISTS",
		"SERVER_STATUS_LAST_ROW_SENT",
		"SERVER_STATUS_DB_DROPPED",
		"SERVER_STATUS_NO_BACKSLASH_ESCAPES",
		"SERVER_STATUS_METADATA_CHANGED",
		"SERVER_QUERY_WAS_SLOW",
		"SERVER_PS_OUT_PARAMS",
		"SERVER_STATUS_IN_TRANS_READONLY",
		"SERVER_SESSION_STATE_CHANGED",
	} {
		if f&1 == 1 {
			if b.Len() > 0 {
				b.WriteString("|")
			}
			b.WriteString(flag)
		}
		f >>= 1
	}

	return b.String()
}

type OKResponse struct {
	AffectedRows uint64
	LastInsertID uint64
	ServerStatus StatusFlags
	WarningCount uint16
	// FIXME: deal with session tracking
	CorePacket
	Info string
}

type PrepareOKResponse struct {
	CorePacket
	StatementID uint32
	NumColumns  uint16
	NumParams   uint16
	Warnings    int16

	Columns []ColumnInfo `json:"Columns,omitempty"`
	Params  []ColumnInfo `json:"Params,omitempty"`
}

type ErrorResponse struct {
	Code uint16
	CorePacket
	State   string `json:"State,omitempty"`
	Message string
}

type ColumnInfo struct {
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
	Capabilities ClientCapabilities
	Collation    byte
	Protocol     byte
	Version      string
	CorePacket
}

type CorePacket struct {
	RawData []byte `json:"RawData,omitempty"`
	Type    string
}

func (p *CorePacket) SetData(d []byte) {
	p.RawData = d
}

type FieldType byte
type FieldDetail uint16
type ResponseType byte

const (
	// MySQLError type.
	MySQLError ResponseType = 0xff
	// MySQLEOF type.
	MySQLEOF ResponseType = 0xfe
	// MySQLOK type.
	MySQLOK ResponseType = 0
	// MySQLLocalInfile type.
	MySQLLocalInfile ResponseType = 0xfb
)

//nolint:revive,stylecheck
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

	CCAP_CLIENT_MYSQL                      ClientCapabilities = 1
	CCAP_FOUND_ROWS                        ClientCapabilities = 2
	CCAP_CONNECT_WITH_DB                   ClientCapabilities = 8
	CCAP_COMPRESS                          ClientCapabilities = 32
	CCAP_LOCAL_FILES                       ClientCapabilities = 128
	CCAP_IGNORE_SPACE                      ClientCapabilities = 256
	CCAP_CLIENT_PROTOCOL_41                ClientCapabilities = 1 << 9
	CCAP_CLIENT_INTERACTIVE                ClientCapabilities = 1 << 10
	CCAP_SSL                               ClientCapabilities = 1 << 11
	CCAP_TRANSACTIONS                      ClientCapabilities = 1 << 12
	CCAP_SECURE_CONNECTION                 ClientCapabilities = 1 << 13
	CCAP_MULTI_STATEMENTS                  ClientCapabilities = 1 << 16
	CCAP_MULTI_RESULTS                     ClientCapabilities = 1 << 17
	CCAP_PS_MULTI_RESULTS                  ClientCapabilities = 1 << 18
	CCAP_PLUGIN_AUTH                       ClientCapabilities = 1 << 19
	CCAP_CONNECT_ATTRS                     ClientCapabilities = 1 << 20
	CCAP_PLUGIN_AUTH_LENENC_CLIENT_DATA    ClientCapabilities = 1 << 21
	CCAP_CLIENT_SESSION_TRACK              ClientCapabilities = 1 << 23
	CCAP_CLIENT_DEPRECATE_EOF              ClientCapabilities = 1 << 24
	CCAP_CLIENT_ZSTD_COMPRESSION_ALGORITHM ClientCapabilities = 1 << 26
	CCAP_CLIENT_CAPABILITY_EXTENSION       ClientCapabilities = 1 << 29
)

func (d FieldDetail) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

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

func (f FieldType) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.String())
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
