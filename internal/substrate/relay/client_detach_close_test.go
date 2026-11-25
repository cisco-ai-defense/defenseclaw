// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// closeSpyConn records when the client drops the TCP connection.
type closeSpyConn struct {
	net.Conn
	closed *atomic.Int64
}

func (c closeSpyConn) Close() error {
	c.closed.CompareAndSwap(0, time.Now().UnixNano())
	return c.Conn.Close()
}

// GAP-2164: a client that detaches sends the detach frame and a close frame.
// It must leave the socket to the relay's answer to the close before it drops
// the connection: a TCP close with the relay's last frames unread is a reset,
// and a reset discards what the relay received and had not read yet (native
// Windows lost the detach frame that way, so the relay never saw the person
// detach and a test waited 10 s for it). The relay here answers the close
// 200 ms after the detach frame, as a busy one does.
func TestAttachDetachWaitsForTheRelaysCloseBeforeDroppingTheSocket(t *testing.T) {
	up := websocket.Upgrader{Subprotocols: []string{Subprotocol}}
	var closeSentAt atomic.Int64
	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.BinaryMessage, EncodeControl(Control{Type: CtlHello, Version: Version, Session: "s"}))
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			typ, payload, err := Decode(msg)
			if err != nil || typ != FrameControl {
				continue
			}
			if ctl, _ := DecodeControl(payload); ctl.Type == CtlDetach {
				time.Sleep(200 * time.Millisecond)
				closeSentAt.Store(time.Now().UnixNano())
				_ = c.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "detach"), time.Now().Add(time.Second))
				return
			}
		}
	}))
	defer srv.Close()

	var droppedAt atomic.Int64
	dialer := &websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return closeSpyConn{Conn: conn, closed: &droppedAt}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pr, pw := ioPipe()
	defer pw.Close()
	go func() { _, _ = pw.Write([]byte{DetachKey}) }()
	res, err := Attach(ctx, pr, &bytes.Buffer{}, AttachOptions{BaseURL: srv.URL, Token: "t", Cols: 80, Rows: 24, Dialer: dialer})
	if err != nil || !res.Detached {
		t.Fatalf("Attach: %+v, %v", res, err)
	}
	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the relay never saw the detach")
	}
	sent, dropped := closeSentAt.Load(), droppedAt.Load()
	if sent == 0 || dropped == 0 {
		t.Fatalf("relay close sent at %d, socket dropped at %d: want both", sent, dropped)
	}
	if dropped < sent {
		t.Fatalf("the client dropped the socket %s before the relay answered the close", time.Duration(sent-dropped))
	}
}
