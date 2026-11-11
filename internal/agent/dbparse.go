package agent

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// database protocols identified by the L7 eBPF program
const (
	protoHTTP     = 1
	protoPostgres = 2
	protoRedis    = 3
	protoMySQL    = 4
	protoCQL      = 5
	protoKafka    = 6
	protoMongo    = 7
	protoMemcache = 8
)

var protoNames = map[uint8]string{
	protoPostgres: "postgres", protoRedis: "redis", protoMySQL: "mysql",
	protoCQL: "cassandra", protoKafka: "kafka", protoMongo: "mongodb", protoMemcache: "memcached",
}

var kafkaAPIs = map[uint16]string{
	0: "Produce", 1: "Fetch", 2: "ListOffsets", 3: "Metadata", 8: "OffsetCommit", 9: "OffsetFetch",
	10: "FindCoordinator", 11: "JoinGroup", 12: "Heartbeat", 13: "LeaveGroup", 14: "SyncGroup",
	15: "DescribeGroups", 16: "ListGroups", 18: "ApiVersions", 19: "CreateTopics", 20: "DeleteTopics",
	22: "InitProducerId", 24: "AddPartitionsToTxn", 26: "EndTxn", 32: "DescribeConfigs", 36: "SaslAuthenticate",
}

var cqlErrors = map[uint32]string{
	0x0000: "ServerError", 0x000A: "ProtocolError", 0x0100: "AuthenticationError", 0x1000: "Unavailable",
	0x1001: "Overloaded", 0x1002: "IsBootstrapping", 0x1003: "TruncateError", 0x1100: "WriteTimeout",
	0x1200: "ReadTimeout", 0x1300: "ReadFailure", 0x1400: "FunctionFailure", 0x1500: "WriteFailure",
	0x2000: "SyntaxError", 0x2100: "Unauthorized", 0x2200: "Invalid", 0x2300: "ConfigError",
	0x2400: "AlreadyExists", 0x2500: "Unprepared",
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func le32(b []byte) uint32 {
	return uint32(b[3])<<24 | uint32(b[2])<<16 | uint32(b[1])<<8 | uint32(b[0])
}

// cqlRequest names a CQL request: the normalized statement for QUERY and
// PREPARE (body starts with a [long string]).
func cqlRequest(b []byte) string {
	if len(b) < 9 {
		return ""
	}
	switch b[4] {
	case 0x07, 0x09:
		body := b[9:]
		if len(body) < 4 {
			return "(query)"
		}
		n := int(be32(body))
		q := body[4:]
		if n > len(q) {
			return truncatedSQL(string(q))
		}
		if n >= 0 {
			q = q[:n]
		}
		return NormalizeSQL(string(q))
	case 0x0A:
		return "(execute prepared statement)"
	case 0x0D:
		return "(batch)"
	}
	return ""
}

// mongoRequest returns "<command> <collection>" from an OP_MSG body section.
func mongoRequest(b []byte) string {
	// header(16) flagBits(4) kind(1) docLen(4) elementType(1) name\0 value
	if len(b) < 27 || b[20] != 0 {
		return "(command)"
	}
	i := 26
	end := bytes.IndexByte(b[i:], 0)
	if end <= 0 {
		return "(command)"
	}
	cmd := string(b[i : i+end])
	j := i + end + 1
	if b[25] == 0x02 && j+4 <= len(b) { // string value: collection name
		n := int(le32(b[j:]))
		s := b[j+4:]
		if n > 0 && n-1 <= len(s) {
			s = s[:n-1]
		}
		return cmd + " " + cstring(s)
	}
	return cmd
}

var (
	sqlString = regexp.MustCompile(`'(?:[^']|'')*'?`)
	sqlNumber = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	sqlSpace  = regexp.MustCompile(`\s+`)
	sqlIn     = regexp.MustCompile(`(?i)\bIN\s*\(\s*\?(?:\s*,\s*\?)*\s*\)`)
)

// NormalizeSQL replaces literals with ? so statements aggregate by shape.
func NormalizeSQL(q string) string {
	q = sqlString.ReplaceAllString(q, "?")
	q = sqlNumber.ReplaceAllString(q, "?")
	q = sqlIn.ReplaceAllString(q, "IN (?)")
	q = strings.TrimSpace(sqlSpace.ReplaceAllString(q, " "))
	q = truncate(q, 100)
	if q == "" {
		q = "(empty)"
	}
	return q
}

// truncatedSQL normalizes a statement that was cut by the capture size: it
// drops the partial last word so the same statement always aggregates under
// the same text, whatever the length of the literals before the cut.
func truncatedSQL(q string) string {
	if i := strings.LastIndexAny(q, " \t\n"); i > 0 {
		q = q[:i]
	}
	return NormalizeSQL(q) + " …"
}

// sqlText normalizes b up to its NUL terminator, marking it truncated when
// the terminator is missing (the statement continues past the capture).
func sqlText(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return NormalizeSQL(string(b[:i]))
	}
	return truncatedSQL(string(b))
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ParseDBRequest extracts a normalized statement (or command) from the first
// bytes of a client request. It returns "" when the bytes are not a request
// after all (the event must then be ignored).
func ParseDBRequest(proto uint8, b []byte) string {
	switch proto {
	case protoPostgres:
		if len(b) < 6 {
			return "(unknown)"
		}
		body := b[5:]
		switch b[0] {
		case 'Q':
			return sqlText(body)
		case 'P': // Parse: statement name \0 query \0
			if i := bytes.IndexByte(body, 0); i >= 0 {
				return sqlText(body[i+1:])
			}
		case 'B':
			return "(execute prepared statement)"
		}
	case protoMySQL:
		if len(b) > 5 {
			plen := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
			q := b[5:]
			if plen-1 > len(q) {
				return truncatedSQL(string(q))
			}
			return NormalizeSQL(cstring(q))
		}
	case protoRedis:
		return redisCommand(b)
	case protoCQL:
		return cqlRequest(b)
	case protoKafka:
		if len(b) < 14 {
			return ""
		}
		api, ok := kafkaAPIs[be16(b[4:])]
		if !ok {
			api = "api-" + strconv.Itoa(int(be16(b[4:])))
		}
		if api == "Fetch" {
			api += " (long poll)"
		}
		// clientId: nullable string after the correlation id
		if n := int(int16(be16(b[12:]))); n > 0 && 14+n <= len(b) {
			api += " client=" + string(b[14:14+n])
		}
		return api
	case protoMongo:
		return mongoRequest(b)
	case protoMemcache:
		if f := strings.Fields(string(bytes.TrimRight(b, "\x00"))); len(f) > 0 {
			return f[0]
		}
	}
	return "(unknown)"
}

// redisCommands are the commands accepted as client requests. A Redis
// server's array replies (LRANGE results, pub/sub messages) have the same
// RESP shape as requests; requiring a known command name filters them out.
var redisCommands = map[string]bool{}

func init() {
	for _, c := range strings.Fields(`APPEND AUTH BITCOUNT BITFIELD BITOP BITPOS BLMOVE BLPOP BRPOP BRPOPLPUSH BZPOPMAX BZPOPMIN
	CLIENT CLUSTER COMMAND CONFIG COPY DBSIZE DECR DECRBY DEL DISCARD DUMP ECHO EVAL EVALSHA EXEC EXISTS EXPIRE EXPIREAT
	FLUSHALL FLUSHDB GEOADD GEODIST GEOHASH GEOPOS GEOSEARCH GET GETDEL GETEX GETRANGE GETSET HDEL HELLO HEXISTS HGET
	HGETALL HINCRBY HINCRBYFLOAT HKEYS HLEN HMGET HMSET HSCAN HSET HSETNX HSTRLEN HVALS INCR INCRBY INCRBYFLOAT INFO KEYS
	LINDEX LINSERT LLEN LMOVE LPOP LPOS LPUSH LPUSHX LRANGE LREM LSET LTRIM MGET MONITOR MOVE MSET MSETNX MULTI OBJECT
	PERSIST PEXPIRE PEXPIREAT PFADD PFCOUNT PFMERGE PING PSETEX PSUBSCRIBE PTTL PUBLISH PUBSUB PUNSUBSCRIBE RANDOMKEY
	READONLY RENAME RENAMENX RESTORE ROLE RPOP RPOPLPUSH RPUSH RPUSHX SADD SCAN SCARD SCRIPT SDIFF SDIFFSTORE SELECT SET
	SETEX SETNX SETRANGE SINTER SINTERSTORE SISMEMBER SMEMBERS SMISMEMBER SMOVE SORT SPOP SRANDMEMBER SREM SSCAN STRLEN
	SUBSCRIBE SUNION SUNIONSTORE SWAPDB TIME TOUCH TTL TYPE UNLINK UNSUBSCRIBE UNWATCH WAIT WATCH XACK XADD XAUTOCLAIM
	XCLAIM XDEL XGROUP XINFO XLEN XPENDING XRANGE XREAD XREADGROUP XREVRANGE XTRIM ZADD ZCARD ZCOUNT ZINCRBY ZINTERSTORE
	ZLEXCOUNT ZMSCORE ZPOPMAX ZPOPMIN ZRANDMEMBER ZRANGE ZRANGEBYLEX ZRANGEBYSCORE ZRANK ZREM ZREMRANGEBYLEX
	ZREMRANGEBYRANK ZREMRANGEBYSCORE ZREVRANGE ZREVRANGEBYLEX ZREVRANGEBYSCORE ZREVRANK ZSCAN ZSCORE ZUNIONSTORE`) {
		redisCommands[c] = true
	}
}

// redisCommand returns the command name (and subcommand for a few) of a RESP
// array request: "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n" -> "GET". It returns ""
// when the first element is not a known command (e.g. a server reply).
func redisCommand(b []byte) string {
	parts := strings.Split(string(b), "\r\n")
	if len(parts) < 3 || !strings.HasPrefix(parts[1], "$") {
		return ""
	}
	cmd := strings.ToUpper(parts[2])
	if !redisCommands[cmd] {
		return ""
	}
	switch cmd {
	case "CLIENT", "CONFIG", "CLUSTER", "XGROUP", "SCRIPT", "OBJECT":
		if len(parts) >= 5 {
			cmd += " " + strings.ToUpper(parts[4])
		}
	}
	if len(cmd) > 40 {
		cmd = cutRunes(cmd, 40)
	}
	return cmd
}

// DBError reports whether the first bytes of a reply carry an error.
func DBError(proto uint8, resp []byte) bool {
	if len(resp) == 0 {
		return false
	}
	switch proto {
	case protoPostgres:
		// walk the messages: with the extended protocol an ErrorResponse
		// comes after ParseComplete ('1') / BindComplete ('2')
		for i := 0; i+5 <= len(resp); {
			if resp[i] == 'E' {
				return true
			}
			n := int(resp[i+1])<<24 | int(resp[i+2])<<16 | int(resp[i+3])<<8 | int(resp[i+4])
			if n < 4 {
				return false
			}
			i += 1 + n
		}
		return len(resp) > 0 && resp[0] == 'E'
	case protoRedis:
		return resp[0] == '-'
	case protoMySQL:
		// 3 byte length, sequence id, then 0xff for ERR packets
		return len(resp) > 4 && resp[4] == 0xff
	case protoCQL:
		return len(resp) > 4 && resp[4] == 0x00 // ERROR opcode
	case protoMemcache:
		s := string(resp)
		return strings.HasPrefix(s, "ERROR") || strings.HasPrefix(s, "SERVER_ERROR") || strings.HasPrefix(s, "CLIENT_ERROR")
	}
	return false
}

// DBErrorKind names the error of a reply when the protocol carries a code.
func DBErrorKind(proto uint8, resp []byte) string {
	switch proto {
	case protoCQL:
		if len(resp) >= 13 {
			code := be32(resp[9:])
			if n, ok := cqlErrors[code]; ok {
				return n
			}
			return "error-" + strconv.FormatUint(uint64(code), 16)
		}
	case protoMemcache:
		if f := strings.Fields(string(bytes.TrimRight(resp, "\x00"))); len(f) > 0 {
			return f[0]
		}
	}
	return ""
}

// dbKey is the EntityStats.DB key: "<protocol name>|<statement>", the same
// form model.EntityStats.Merge uses for its overflow bucket.
func dbKey(proto uint8, q string) string { return protoNames[proto] + "|" + q }
