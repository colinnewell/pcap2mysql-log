package decoding

import (
	"fmt"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
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
	Emit Emitter
}

func (m *RequestDecoder) Write(p []byte) (int, error) {
	// FIXME: check we have enough bytes
	switch t := CommandCode(p[packet.HeaderLen]); t {
	case reqStmtPrepare:
		query := p[packet.HeaderLen+1:]
		m.Emit.Transmission(structure.Request{Type: "Prepare", Query: string(query)})
	case reqQuery:
		query := p[packet.HeaderLen+1:]
		m.Emit.Transmission(structure.Request{Type: "Query", Query: string(query)})
	case reqQuit:
		m.Emit.Transmission(structure.Request{Type: "QUIT"})
	case reqStmtExecute:
		// int<1> 0x17 : COM_STMT_EXECUTE header
		// int<4> statement id
		// int<1> flags:
		// int<4> Iteration count (always 1)
		// if (param_count > 0)
		// byte<(param_count + 7)/8> null bitmap
		// byte<1>: send type to server (0 / 1)
		// if (send type to server)
		// for each parameter :
		// byte<1>: field type
		// byte<1>: parameter flag
		// for each parameter (i.e param_count times)
		// byte<n> binary parameter value
		m.Emit.Transmission(structure.Request{Type: "Execute"})
	default:
		m.Emit.Transmission(structure.Request{Type: t.String()})
	}
	return len(p), nil
}
