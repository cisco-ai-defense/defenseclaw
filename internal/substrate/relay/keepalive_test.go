// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// LC-J9a: a network that drops without a reset leaves the socket open. The
// client notices within KeepaliveDead (no frame, no pong) and returns, so the
// launcher says the connection is lost and reconnects.
func TestAttachNoticesASilentRelay(t *testing.T) {
	up := websocket.Upgrader{Subprotocols: []string{Subprotocol}}
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.BinaryMessage, EncodeControl(Control{Type: CtlHello, Version: Version, Session: "s"}))
		<-release // never reads: no pong, nothing more
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pr, pw := ioPipe()
	defer pw.Close()
	start := time.Now()
	_, _ = Attach(ctx, pr, &bytes.Buffer{}, AttachOptions{BaseURL: srv.URL, Token: "t", Cols: 80, Rows: 24,
		KeepaliveEvery: 50 * time.Millisecond, KeepaliveDead: 300 * time.Millisecond})
	if d := time.Since(start); d > 5*time.Second || ctx.Err() != nil {
		t.Fatalf("a silent relay was noticed after %s", d)
	}
}

// A relay that answers pings keeps the connection up past KeepaliveDead.
func TestAttachKeepaliveHoldsAQuietButLiveRelay(t *testing.T) {
	up := websocket.Upgrader{Subprotocols: []string{Subprotocol}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.BinaryMessage, EncodeControl(Control{Type: CtlHello, Version: Version, Session: "s"}))
		for { // reading answers pings (gorilla default handler)
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	pr, pw := ioPipe()
	defer pw.Close()
	_, _ = Attach(ctx, pr, &bytes.Buffer{}, AttachOptions{BaseURL: srv.URL, Token: "t", Cols: 80, Rows: 24,
		KeepaliveEvery: 50 * time.Millisecond, KeepaliveDead: 300 * time.Millisecond})
	if ctx.Err() == nil {
		t.Fatal("a live relay that answers pings was dropped before the test ended")
	}
}

func ioPipe() (*io.PipeReader, *io.PipeWriter) { return io.Pipe() }
