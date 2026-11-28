// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Port stream bounds (B3.2). A forward reaches 127.0.0.1:N in the actor
// only, for N in MinForwardPort-65535 other than the relay's own port.
const (
	MinForwardPort  = 1024
	portDialTimeout = 5 * time.Second
	portChunk       = 32 << 10
)

// PortError is the one text (control) message of a port stream: binary
// messages are the TCP bytes, a text message says why the stream ends.
type PortError struct {
	Type string `json:"type"` // "error"
	Code string `json:"code"` // nothing_listening
}

// PortErrNothingListening is the code when no process listens on the port.
const PortErrNothingListening = "nothing_listening"

// listenPort is the relay's own TCP port (never forwarded); 0 when unknown.
func (s *Server) listenPort() int {
	_, p, err := net.SplitHostPort(s.opts.Config.Relay.Listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// servePort carries one TCP connection to 127.0.0.1:N in the actor over one
// WebSocket, under a token scoped to port:N only (dc.scope).
func (s *Server) servePort(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("port")
	n, err := strconv.Atoi(target)
	if err != nil || strconv.Itoa(n) != target || n < MinForwardPort || n > 65535 {
		http.Error(w, "relay: a forwarded port is a number from 1024 to 65535", http.StatusNotFound)
		return
	}
	if n == s.listenPort() {
		http.Error(w, "relay: the relay's own port is not forwarded", http.StatusForbidden)
		return
	}
	if _, ok := s.authScope(w, r, "port", true, "port:"+target); !ok {
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	var d net.Dialer
	tcp, err := d.DialContext(r.Context(), "tcp", net.JoinHostPort("127.0.0.1", target))
	if err != nil {
		b, _ := json.Marshal(PortError{Type: "error", Code: PortErrNothingListening})
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = conn.WriteMessage(websocket.TextMessage, b)
		return
	}
	PipePort(conn, tcp)
}

// PipePort copies between a port-stream WebSocket and its TCP connection
// until either side ends, then closes both. Both ends use it: the relay
// with the actor's port, the launcher with the laptop's accepted socket.
// A text message ends the stream (PortError); it is never data.
func PipePort(conn *websocket.Conn, tcp net.Conn) error {
	defer tcp.Close()
	conn.SetReadLimit(portChunk * 2)
	var wmu sync.Mutex
	var once sync.Once
	var end error
	stop := func(err error) {
		once.Do(func() {
			end = err
			_ = tcp.Close()
			wmu.Lock()
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
			wmu.Unlock()
			_ = conn.Close()
		})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, portChunk)
		for {
			k, err := tcp.Read(buf)
			if k > 0 {
				wmu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				werr := conn.WriteMessage(websocket.BinaryMessage, buf[:k])
				wmu.Unlock()
				if werr != nil {
					stop(werr)
					return
				}
			}
			if err != nil {
				stop(nil)
				return
			}
		}
	}()
	for {
		kind, rd, err := conn.NextReader()
		if err != nil {
			stop(nil)
			break
		}
		if kind != websocket.BinaryMessage {
			var pe PortError
			b, _ := io.ReadAll(io.LimitReader(rd, 512))
			_ = json.Unmarshal(b, &pe)
			stop(&PortStreamError{Code: pe.Code})
			break
		}
		if _, err := io.Copy(tcp, rd); err != nil {
			stop(err)
			break
		}
	}
	<-done
	return end
}

// PortStreamError is a port stream the other end ended with a PortError.
type PortStreamError struct{ Code string }

func (e *PortStreamError) Error() string {
	if e.Code == PortErrNothingListening {
		return "nothing is listening on that port in the agent"
	}
	return "the port stream ended: " + e.Code
}
