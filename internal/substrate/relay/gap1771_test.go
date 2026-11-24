// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rel-1-0-10:GAP-1771 (P4, the RV-ATTACH2 follow-ups of GAP-1765).

// A long-poll write the relay read whole, then the connection failed before
// its answer, on a live attachment: the relay may have handed the keys to the
// agent, so they count in Sent (the next hello's Received settles it) and are
// not reported unsent; before, a network error reported them unsent even when
// the relay had written them (the user typed them twice).
func TestGAP1771PollWriteWithNoAnswerCountsSent(t *testing.T) {
	var delivered atomic.Int64
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/poll"):
			_, _ = w.Write([]byte(`{"id":"p1"}`))
		case r.Method == http.MethodGet:
			if gets.Add(1) == 1 {
				w.Header().Set("X-Dcrelay-Cursor", "1")
				_, _ = w.Write(AppendStream(nil, EncodeControl(Control{Type: CtlHello, Version: Version, Session: "s1"})))
				return
			}
			<-r.Context().Done()
		case r.Method == http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			frames, _ := SplitStream(b)
			for _, f := range frames {
				if typ, p, err := Decode(f); err == nil && typ == FrameData {
					delivered.Add(int64(len(p)))
				}
			}
			// The keys reached the agent; the connection drops before the 204.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { time.Sleep(100 * time.Millisecond); _, _ = pw.Write([]byte("keys\r")) }()
	var unsent atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := Attach(ctx, pr, io.Discard, AttachOptions{BaseURL: srv.URL, Token: "t", LongPoll: true, FlatRoutes: true,
		OnUnsent: func(n int) { unsent.Add(int64(n)) }})
	if err != nil {
		t.Fatal(err)
	}
	if delivered.Load() != int64(len("keys\r")) {
		t.Fatalf("the relay got %d key bytes, want %d", delivered.Load(), len("keys\r"))
	}
	if unsent.Load() != 0 || res.Sent != int64(len("keys\r")) {
		t.Fatalf("the relay wrote the keys to the agent, but Sent=%d unsent=%d (want Sent=%d, unsent=0: the launcher says type them again)",
			res.Sent, unsent.Load(), len("keys\r"))
	}
}
