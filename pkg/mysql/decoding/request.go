package decoding

import (
	"fmt"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
)

type CommandCode byte

const (
	reqSleep CommandCode = iota
	reqQuit
	reqInitDB
	reqQuery
	reqFieldList
	reqCreateDB
	reqDropDB
	reqRefresh
	reqShutdown
	reqStatistics
	reqProcessInfo
	reqConnect
	reqProcessKill
	reqDebug
	reqPing
	reqTime
	reqDelayInsert
	reqChangeUser
	reqBinlogDump
	reqTableDump
	reqConnectOut
	reqRegisterSlave
	reqStmtPrepare
	reqStmtExecute
	reqStmtSendLongData
	reqStmtClose
	reqStmtReset
	reqSetOption
	reqStmtFetch
	reqDaemon
	reqBinlogDumpGtid
	reqResetConnection
)

func (c CommandCode) String() string {
	switch c {
	case reqSleep:
		return "MYSQL_SLEEP"
	case reqQuit:
		return "MYSQL_QUIT"
	case reqInitDB:
		return "MYSQL_INIT_DB"
	case reqQuery:
		return "MYSQL_QUERY"
	case reqFieldList:
		return "MYSQL_FIELD_LIST"
	case reqCreateDB:
		return "MYSQL_CREATE_DB"
	case reqDropDB:
		return "MYSQL_DROP_DB"
	case reqRefresh:
		return "MYSQL_REFRESH"
	case reqShutdown:
		return "MYSQL_SHUTDOWN"
	case reqStatistics:
		return "MYSQL_STATISTICS"
	case reqProcessInfo:
		return "MYSQL_PROCESS_INFO"
	case reqConnect:
		return "MYSQL_CONNECT"
	case reqProcessKill:
		return "MYSQL_PROCESS_KILL"
	case reqDebug:
		return "MYSQL_DEBUG"
	case reqPing:
		return "MYSQL_PING"
	case reqTime:
		return "MYSQL_TIME"
	case reqDelayInsert:
		return "MYSQL_DELAY_INSERT"
	case reqChangeUser:
		return "MYSQL_CHANGE_USER"
	case reqBinlogDump:
		return "MYSQL_BINLOG_DUMP"
	case reqTableDump:
		return "MYSQL_TABLE_DUMP"
	case reqConnectOut:
		return "MYSQL_CONNECT_OUT"
	case reqRegisterSlave:
		return "MYSQL_REGISTER_SLAVE"
	case reqStmtPrepare:
		return "MYSQL_STMT_PREPARE"
	case reqStmtExecute:
		return "MYSQL_STMT_EXECUTE"
	case reqStmtSendLongData:
		return "MYSQL_STMT_SEND_LONG_DATA"
	case reqStmtClose:
		return "MYSQL_STMT_CLOSE"
	case reqStmtReset:
		return "MYSQL_STMT_RESET"
	case reqSetOption:
		return "MYSQL_SET_OPTION"
	case reqStmtFetch:
		return "MYSQL_STMT_FETCH"
	case reqDaemon:
		return "MYSQL_DAEMON"
	case reqBinlogDumpGtid:
		return "MYSQL_BINLOG_DUMP_GTID"
	case reqResetConnection:
		return "MYSQL_RESET_CONNECTION"
	}
	return fmt.Sprintf("Unrecognised command: %d", c)
}

type RequestDecoder struct {
	Emit structure.Emitter
}

func (m *RequestDecoder) Write(p []byte) (int, error) {
	// FIXME: check we have enough bytes
	switch t := CommandCode(p[packet.HeaderLen]); t {
	case reqStmtPrepare:
		m.Emit.Transmission(structure.Request{Type: "Prepare"})
	case reqQuery:
		query := p[packet.HeaderLen+1:]
		m.Emit.Transmission(structure.Request{Type: "Query", Query: string(query)})
	case reqQuit:
		m.Emit.Transmission(structure.Request{Type: "QUIT"})
	default:
		m.Emit.Transmission(structure.Request{Type: t.String()})
	}
	return len(p), nil
}