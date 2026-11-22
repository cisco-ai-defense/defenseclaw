// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type gap0534Sink struct {
	mu   sync.Mutex
	seen map[string]int // kind -> count
}

func (s *gap0534Sink) ObserveActivity(kind, _, _ string, _ time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]int{}
	}
	s.seen[kind]++
}

func (s *gap0534Sink) count(kind string) int { s.mu.Lock(); defer s.mu.Unlock(); return s.seen[kind] }

// substrate-1 GAP-0534: a controller without a CPU feed keeps an attached
// actor, so the attach route reports a terminal attachment while it is
// open: a WebSocket every substrateAttachReportEvery until it closes, and
// each long-poll request but its close. Other attach routes (status, files,
// exec, task) are not a terminal.
func TestGAP0534AttachRouteReportsAnOpenAttachment(t *testing.T) {
	old := substrateAttachReportEvery
	substrateAttachReportEvery = 20 * time.Millisecond
	defer func() { substrateAttachReportEvery = old }()
	f := newSubstrateFixture(t)
	up := websocket.Upgrader{}
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dcrelay/1/ws" {
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer relaySrv.Close()
	sink := &gap0534Sink{}
	st := f.api.substrateState()
	st.cfg.Relays = &dialRelay{addr: strings.TrimPrefix(relaySrv.URL, "http://")}
	st.cfg.Activity = sink
	srv := httptest.NewServer(f.admin)
	defer srv.Close()
	base := srv.URL + "/api/v1/substrate/actors/eng-web/alice-1/attach"
	do := func(method, path string) {
		req, _ := http.NewRequest(method, base+path, nil)
		req.Header.Set("Authorization", "Bearer p-alice")
		req.Header.Set("X-DefenseClaw-Client", "launcher") // the admin CSRF gate
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
		}
	}
	do(http.MethodGet, "/status")
	do(http.MethodDelete, "/poll/abc")
	if n := sink.count(SubstrateActivityAttach); n != 0 {
		t.Fatalf("status and a poll close reported %d attachments", n)
	}
	do(http.MethodGet, "/poll/abc")
	if n := sink.count(SubstrateActivityAttach); n != 1 {
		t.Fatalf("a long-poll read reported %d attachments, want 1", n)
	}

	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(base, "http"), http.Header{"Authorization": {"Bearer p-alice"}})
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for sink.count(SubstrateActivityAttach) < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := sink.count(SubstrateActivityAttach); n < 5 {
		t.Fatalf("an open WebSocket attachment reported %d times in 5 s", n)
	}
	_ = ws.Close()
	time.Sleep(100 * time.Millisecond) // the proxy sees the close
	after := sink.count(SubstrateActivityAttach)
	time.Sleep(10 * substrateAttachReportEvery)
	if n := sink.count(SubstrateActivityAttach); n != after {
		t.Fatalf("a closed attachment is still reported: %d -> %d", after, n)
	}
}
