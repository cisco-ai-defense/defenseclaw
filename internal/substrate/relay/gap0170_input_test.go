// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// helloOf dials the relay with query q and returns its hello.
func helloOf(t *testing.T, srv *httptest.Server, tok, q string) (*websocket.Conn, Control) {
	t.Helper()
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}, HandshakeTimeout: 5 * time.Second}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	c, _, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/dcrelay/1/ws?cols=100&rows=30"+q, h)
	if err != nil {
		t.Fatal(err)
	}
	var hello Control
	readUntil(t, c, "ctl:hello", func(cc Control) {
		if cc.Type == CtlHello {
			hello = cc
		}
	})
	return c, hello
}

// GAP-0170: every attachment's hello names its input count; a reconnect
// that resumes it is told how many DATA bytes the relay wrote to the agent
// from it, only when it is the same person's.
func TestHelloSaysWhatTheLastAttachmentDelivered(t *testing.T) {
	needLinux(t)
	s, _, ec := testServer(t, []string{"sh", "-c", `while read l; do echo "got:$l"; done`})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	tok := func(person string) string {
		return ec.token(t, claims(time.Now(), func(c map[string]any) {
			if person != "" {
				c["sub"] = person
			}
		}), TokenType)
	}
	c1, h1 := helloOf(t, srv, tok(""), "")
	if h1.Input == "" || h1.Received != nil {
		t.Fatalf("first hello %+v, want an input id and no received count", h1)
	}
	c1.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("abc\r")))
	c1.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("de\r")))
	readUntil(t, c1, "got:de", nil)
	c1.Close()

	c2, h2 := helloOf(t, srv, tok(""), "&resume="+h1.Input)
	defer c2.Close()
	if h2.Received == nil || *h2.Received != 7 || h2.Input == "" || h2.Input == h1.Input {
		t.Fatalf("resumed hello %+v, want received 7 and a new input id", h2)
	}
	c3, h3 := helloOf(t, srv, tok("mallory@example.test"), "&resume="+h1.Input)
	defer c3.Close()
	if h3.Received != nil {
		t.Fatalf("another person's resume got a count: %+v", h3)
	}
	c4, h4 := helloOf(t, srv, tok(""), "&resume=unknown")
	defer c4.Close()
	if h4.Received != nil {
		t.Fatalf("an unknown resume got a count: %+v", h4)
	}
}

// The counts kept are bounded: the oldest attachment's goes first.
func TestInputCountsAreBounded(t *testing.T) {
	s := NewServer(Options{})
	first, _, _ := s.countInput("alice", "")
	for i := 0; i < maxInputCounts; i++ {
		s.countInput("alice", "")
	}
	if _, _, got := s.countInput("alice", first); got != nil || len(s.inputs) != maxInputCounts {
		t.Fatalf("kept %d counts, first still known: %v", len(s.inputs), got != nil)
	}
}
