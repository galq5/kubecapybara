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
)

var protoNames = map[uint8]string{protoPostgres: "postgres", protoRedis: "redis", protoMySQL: "mysql"}

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
	if len(q) > 100 {
		q = q[:100] + "…"
	}
	if q == "" {
		q = "(empty)"
	}
	return q
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
			return NormalizeSQL(cstring(body))
		case 'P': // Parse: statement name \0 query \0
			if i := bytes.IndexByte(body, 0); i >= 0 {
				return NormalizeSQL(cstring(body[i+1:]))
			}
		case 'B':
			return "(execute prepared statement)"
		}
	case protoMySQL:
		if len(b) > 5 {
			return NormalizeSQL(cstring(b[5:]))
		}
	case protoRedis:
		return redisCommand(b)
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
		cmd = cmd[:40]
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
	}
	return false
}

func dbKey(proto uint8, q string) string { return strconv.Itoa(int(proto)) + "|" + q }
