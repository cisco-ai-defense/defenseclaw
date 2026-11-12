// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakePeer is a relay that says hello, prints a little and then exits, or
// keeps printing until the client leaves. It needs no tmux.
func fakePeer(t *testing.T, exitAfterHello bool) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{Subprotocols: []string{Subprotocol}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dcrelay/1/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.BinaryMessage, EncodeControl(Control{Type: CtlHello, Version: Version, Session: "s1"}))
		if exitAfterHello {
			code := 3
			_ = c.WriteMessage(websocket.BinaryMessage, EncodeControl(Control{Type: CtlExit, Code: &code}))
			return
		}
		go func() {
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for i := 0; i < 200; i++ {
			if c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("x"))) != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	mux.HandleFunc("POST /dcrelay/1/poll", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"p1","cursor":"0"}`)
	})
	mux.HandleFunc("GET /dcrelay/1/poll/{id}", func(w http.ResponseWriter, r *http.Request) {
		code := 0
		frames := AppendStream(nil, EncodeControl(Control{Type: CtlHello, Session: "s2"}))
		frames = AppendStream(frames, EncodeControl(Control{Type: CtlExit, Code: &code}))
		w.Header().Set("X-Dcrelay-Cursor", "1")
		_, _ = w.Write(frames)
	})
	mux.HandleFunc("POST /dcrelay/1/poll/{id}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("DELETE /dcrelay/1/poll/{id}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestAttachResultIsNotRacy runs the paths that return the result while the
// reader goroutine is still writing it (GAP-0088); go test -race -count=100
// must stay quiet.
func TestAttachResultIsNotRacy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		longPoll bool
		exit     bool
		input    string
	}{
		{"websocket detach", false, false, string([]byte{DetachKey})},
		{"websocket exit", false, true, "hi"},
		{"long-poll detach", true, false, string([]byte{DetachKey})},
		{"long-poll exit", true, true, "hi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakePeer(t, tc.exit)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			res, err := Attach(ctx, strings.NewReader(tc.input), io.Discard, AttachOptions{BaseURL: srv.URL, Token: "t", LongPoll: tc.longPoll})
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Session
			_ = res.ExitCode
			_ = res.Detached
		})
	}
}
