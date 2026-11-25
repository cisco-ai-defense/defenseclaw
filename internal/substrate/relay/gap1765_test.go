// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// lateWrites is a connection whose writes after the handshake reach the
// peer at once but return late, as when the writing goroutine is not
// scheduled back right after the write.
type lateWrites struct {
	net.Conn
	n atomic.Int32
}

func (c *lateWrites) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.n.Add(1) > 1 {
		time.Sleep(300 * time.Millisecond)
	}
	return n, err
}

// GAP-1765: keys the relay got just before it dropped the connection are in
// Sent even when the attachment ends before the write that carried them has
// returned. Sent was read without waiting for that write, so the launcher
// never said those keys may not have reached the agent.
func TestSentCountsAWriteThatReturnsAfterTheDrop(t *testing.T) {
	up := websocket.Upgrader{Subprotocols: []string{Subprotocol}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.BinaryMessage, EncodeControl(Control{Type: CtlHello, Version: Version, Session: "s1"}))
		// The first DATA frame drops the connection, as a suspend does.
		_, _, _ = c.ReadMessage()
	}))
	defer srv.Close()
	d := &websocket.Dialer{HandshakeTimeout: 5 * time.Second, NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var nd net.Dialer
		c, err := nd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &lateWrites{Conn: c}, nil
	}}
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write([]byte("LOSE\r")) }()
	var unsent atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := Attach(ctx, pr, io.Discard, AttachOptions{BaseURL: srv.URL, Token: "t", Dialer: d,
		OnUnsent: func(b []byte) { unsent.Add(int64(len(b))) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 5 || unsent.Load() != 0 {
		t.Fatalf("Sent %d, unsent %d; want 5 sent and none unsent", res.Sent, unsent.Load())
	}
}
