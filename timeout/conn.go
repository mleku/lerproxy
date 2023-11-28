package timeout

import (
	log2 "mleku.online/git/log"
	"net"
	"time"
)

var (
	log   = log2.GetLogger()
	fails = log.E.Chk
)

// Conn extends deadline after successful read or write operations
type Conn struct {
	time.Duration
	*net.TCPConn
}

func (c Conn) Read(b []byte) (n int, e error) {
	if n, e = c.TCPConn.Read(b); !fails(e) {
		if e = c.SetDeadline(c.getTimeout()); fails(e) {
		}
	}
	return
}

func (c Conn) Write(b []byte) (n int, e error) {
	if n, e = c.TCPConn.Write(b); !fails(e) {
		if e = c.SetDeadline(c.getTimeout()); fails(e) {
		}
	}
	return
}

func (c Conn) getTimeout() (t time.Time) { return time.Now().Add(c.Duration) }
