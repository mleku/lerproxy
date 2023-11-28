package tcpkeepalive

import (
	"mleku.online/git/lerproxy/timeout"
	log2 "mleku.online/git/log"
	"net"
	"time"
)

var (
	log   = log2.GetLogger()
	fails = log.E.Chk
)

// Period can be changed prior to opening a Listener to alter its'
// KeepAlivePeriod.
var Period = 3 * time.Minute

// Listener sets TCP keep-alive timeouts on accepted connections.
// It's used by ListenAndServe and ListenAndServeTLS so dead TCP connections
// (e.g. closing laptop mid-download) eventually go away.
type Listener struct {
	time.Duration
	*net.TCPListener
}

func (ln Listener) Accept() (conn net.Conn, e error) {
	var tc *net.TCPConn
	if tc, e = ln.AcceptTCP(); fails(e) {
		return
	}
	if e = tc.SetKeepAlive(true); fails(e) {
		return
	}
	if e = tc.SetKeepAlivePeriod(Period); fails(e) {
		return
	}
	if ln.Duration != 0 {
		return timeout.Conn{Duration: ln.Duration, TCPConn: tc}, nil
	}
	return tc, nil
}
