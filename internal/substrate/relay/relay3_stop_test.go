// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

// guardServer is a relay whose agent prints what it reads, with
// ~/.gemini guarded.
func guardServer(t *testing.T, argv []string) (*Server, *recorder, signer, string, *httptest.Server) {
	t.Helper()
	gem := filepath.Join(t.TempDir(), ".gemini")
	if err := os.Mkdir(gem, 0o755); err != nil {
		t.Fatal(err)
	}
	s, rec, ec := testServer(t, argv)
	s.opts.Config.Relay.Connector = "antigravity"
	s.opts.Guard = []string{gem}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, rec, ec, gem, srv
}

// GAP-0357: after the guard stopped the agent, an attach, a long-poll
// attach and the status route answer 410 with the guard's reason, so the
// launcher says why instead of "it belongs to someone else". The trip is
// reported for the audit log (GAP-0120).
func TestGuardStopIsRefusedWithItsReason(t *testing.T) {
	_, rec, ec, gem, srv := guardServer(t, []string{"sh", "-c", "while read l; do echo got:$l; done"})
	c, _, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("one\r")))
	readUntil(t, c, "got:one", nil)
	if err := os.Rename(gem, gem+".x"); err != nil {
		t.Fatal(err)
	}
	readUntil(t, c, "integrity guard", nil)

	_, resp, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusGone || resp.Header.Get(StoppedHeader) != "guard" {
		t.Fatalf("a new attachment: %v %v", resp, err)
	}
	for _, rq := range []struct{ method, path string }{{"POST", "/dcrelay/1/poll"}, {"GET", "/dcrelay/1/status"}} {
		req, _ := http.NewRequest(rq.method, srv.URL+rq.path, nil)
		req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusGone || !strings.Contains(string(body), "integrity guard") || !strings.Contains(string(body), "delete it and start a new one") {
			t.Errorf("%s %s after the trip: %d %q", rq.method, rq.path, r.StatusCode, body)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(strings.Join(rec.list(), "\n"), "tamper antigravity: ") {
		time.Sleep(20 * time.Millisecond)
	}
	if got := strings.Join(rec.list(), "\n"); !strings.Contains(got, "tamper antigravity: "+gem+" was moved") {
		t.Fatalf("the trip was not reported for the audit log: %q", got)
	}
}

// GAP-0358: a process the agent started in a session of its own (a
// job-control shell, a daemon) is stopped with the agent, and the attached
// terminal is closed, not left answering.
func TestGuardStopsTheWholeTreeAndClosesTerminals(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "survivor.pid")
	agent := "setsid sh -c 'echo $$ > " + marker + "; exec sleep 300' & while read l; do echo got:$l; done"
	_, _, ec, gem, srv := guardServer(t, []string{"sh", "-c", agent})
	c, _, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("one\r")))
	readUntil(t, c, "got:one", nil)
	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for pid == 0 && time.Now().Before(deadline) {
		b, _ := os.ReadFile(marker)
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("the agent's own-session child did not start")
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if sid, _ := unix.Getsid(pid); sid != pid {
		t.Fatalf("the child is not in a session of its own (sid %d)", sid)
	}
	if err := os.Rename(gem, gem+".x"); err != nil {
		t.Fatal(err)
	}
	// The terminal says why and then closes.
	readUntil(t, c, "integrity guard", nil)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := c.ReadMessage(); err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				t.Fatal("the attached terminal stayed open after the guard stopped the agent")
			}
			break
		}
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && alive(pid) {
		time.Sleep(20 * time.Millisecond)
	}
	if alive(pid) {
		t.Fatalf("the agent's child in its own session (pid %d) survived the guard", pid)
	}
}

// alive reports a process that exists and is not a zombie.
func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	st := string(b)
	i := strings.LastIndexByte(st, ')')
	return i < 0 || i+2 >= len(st) || st[i+2] != 'Z'
}
