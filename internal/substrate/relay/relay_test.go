// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// The test binary is the relay's run-agent wrapper in the tmux tests, as the
// relay binary is in an actor.
// The test binary doubles as a probe of hardenProcess: run with
// "harden-probe" it hardens itself and prints its dumpable flag.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "harden-probe" {
		if err := hardenProcess(); err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		d, err := dumpable()
		fmt.Println("dumpable", d, err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestFramesRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		t byte
		p []byte
	}{{FrameData, []byte("ls\r")}, {FrameResize, []byte(`{"cols":120,"rows":40}`)}, {FrameControl, []byte(`{"type":"detach"}`)}} {
		ft, fp, err := Decode(Encode(tc.t, tc.p))
		if err != nil || ft != tc.t || !bytes.Equal(fp, tc.p) {
			t.Fatalf("%x: %x %q %v", tc.t, ft, fp, err)
		}
	}
	if _, _, err := Decode([]byte{0x09, 1}); err == nil {
		t.Fatal("unknown type accepted")
	}
	if _, _, err := Decode(nil); err == nil {
		t.Fatal("empty frame accepted")
	}
	if _, err := DecodeResize([]byte(`{"cols":0,"rows":10}`)); err == nil {
		t.Fatal("zero size accepted")
	}
	if _, err := DecodeResize([]byte(`{"cols":5000,"rows":10}`)); err == nil {
		t.Fatal("huge size accepted")
	}
	var s []byte
	s = AppendStream(s, Encode(FrameData, []byte("a")))
	s = AppendStream(s, EncodeControl(Control{Type: CtlPing}))
	frames, err := SplitStream(s)
	if err != nil || len(frames) != 2 || frames[0][0] != FrameData {
		t.Fatalf("stream %v %v", frames, err)
	}
	if _, err := SplitStream(s[:len(s)-1]); err == nil {
		t.Fatal("truncated stream accepted")
	}
	if _, err := SplitStream([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("zero-length frame accepted")
	}
}

func TestRingCursorResetAndWake(t *testing.T) {
	r := newRing(16)
	r.Append(Encode(FrameData, []byte("0123456789")))
	r.Append(Encode(FrameData, []byte("abcdefghij")))
	data, next, reset, _ := r.Read(context.Background(), 0)
	if !reset {
		t.Fatal("a cursor behind the window must reset")
	}
	frames, _ := SplitStream(data)
	if len(frames) != 1 || string(frames[0][1:]) != "abcdefghij" {
		t.Fatalf("frames %q", frames)
	}
	got := make(chan []byte, 1)
	go func() {
		d, _, _, _ := r.Read(context.Background(), next)
		got <- d
	}()
	time.Sleep(20 * time.Millisecond)
	r.Append(Encode(FrameData, []byte("x")))
	select {
	case d := <-got:
		if f, _ := SplitStream(d); len(f) != 1 || string(f[0][1:]) != "x" {
			t.Fatalf("woken read %q", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader not woken")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if d, _, _, _ := r.Read(ctx, next+100); len(d) != 0 {
		t.Fatal("read past the end returned data")
	}
	r.Close()
	if _, _, _, closed := r.Read(context.Background(), 0); !closed {
		t.Fatal("closed ring not reported")
	}
}

type signer struct {
	kid string
	alg string
	key crypto.Signer
}

func (s signer) token(t *testing.T, claims map[string]any, typ string) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": s.alg, "kid": s.kid, "typ": typ})
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	var sig []byte
	switch k := s.key.(type) {
	case *ecdsa.PrivateKey:
		d := sha256.Sum256([]byte(in))
		r, ss, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		ss.FillBytes(sig[32:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(in))
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

var self = Identity{Atespace: "a5-eng", Name: "cc-1", UID: "uid-1"}

func claims(now time.Time, mut func(map[string]any)) map[string]any {
	c := map[string]any{
		"iss": "https://defenseclaw-admin", "sub": "alice@example.test", "aud": []string{"dcrelay"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": newID(),
		"dc.actor": map[string]string{"atespace": self.Atespace, "actorName": self.Name, "actorUID": self.UID},
	}
	if mut != nil {
		mut(c)
	}
	return c
}

func testVerifier(t *testing.T) (*KeyVerifier, signer, signer) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	v := &KeyVerifier{
		Keys:     map[string]crypto.PublicKey{"ec1": &ec.PublicKey, "ed1": ed.Public()},
		Audience: "dcrelay", Issuer: "https://defenseclaw-admin",
		Self: func() (Identity, error) { return self, nil },
	}
	return v, signer{"ec1", "ES256", ec}, signer{"ed1", "EdDSA", ed}
}

func TestSessionTokens(t *testing.T) {
	v, ec, ed := testVerifier(t)
	now := time.Now()
	for _, s := range []signer{ec, ed} {
		sess, err := v.VerifyToken(s.token(t, claims(now, nil), TokenType))
		if err != nil || sess.Person != "alice@example.test" || sess.Actor != "a5-eng/cc-1" || sess.ActorUID != "uid-1" {
			t.Fatalf("%s: %+v %v", s.alg, sess, err)
		}
	}
	bad := map[string]string{
		"expired":    ec.token(t, claims(now, func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() }), TokenType),
		"not yet":    ec.token(t, claims(now, func(c map[string]any) { c["nbf"] = now.Add(5 * time.Minute).Unix() }), TokenType),
		"too long":   ec.token(t, claims(now, func(c map[string]any) { c["exp"] = now.Add(3 * time.Hour).Unix() }), TokenType),
		"wrong aud":  ec.token(t, claims(now, func(c map[string]any) { c["aud"] = "defenseclaw" }), TokenType),
		"wrong iss":  ec.token(t, claims(now, func(c map[string]any) { c["iss"] = "https://evil" }), TokenType),
		"actor sub":  ec.token(t, claims(now, func(c map[string]any) { c["sub"] = "actor/a5-eng/cc-1" }), TokenType),
		"worker sub": ec.token(t, claims(now, func(c map[string]any) { c["sub"] = "worker-for-actor/a5-eng/cc-1" }), TokenType),
		"other actor": ec.token(t, claims(now, func(c map[string]any) {
			c["dc.actor"] = map[string]string{"atespace": "a5-eng", "actorName": "cc-2", "actorUID": "uid-2"}
		}), TokenType),
		"fork (new uid)": ec.token(t, claims(now, func(c map[string]any) {
			c["dc.actor"] = map[string]string{"atespace": "a5-eng", "actorName": "cc-1", "actorUID": "uid-0"}
		}), TokenType),
		"no actor":    ec.token(t, claims(now, func(c map[string]any) { delete(c, "dc.actor") }), TokenType),
		"typ jwt":     ec.token(t, claims(now, nil), "JWT"),
		"alg swap":    signer{"ec1", "EdDSA", ed.key}.token(t, claims(now, nil), TokenType),
		"unknown kid": signer{"zz", "ES256", ec.key}.token(t, claims(now, nil), TokenType),
		"not a jws":   "abc.def",
		"alg none":    base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"ec1","typ":"dcrelay+jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".",
	}
	tamper := ec.token(t, claims(now, nil), TokenType)
	p := strings.Split(tamper, ".")
	c2, _ := json.Marshal(claims(now, func(c map[string]any) { c["sub"] = "mallory@example.test" }))
	bad["tampered"] = p[0] + "." + base64.RawURLEncoding.EncodeToString(c2) + "." + p[2]
	for name, tok := range bad {
		if _, err := v.VerifyToken(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r := httptest.NewRequest("GET", "/dcrelay/1/ws", nil)
	r.Header.Set("Sec-WebSocket-Protocol", Subprotocol+", "+TokenProtocol+ed.token(t, claims(now, nil), TokenType))
	if _, err := v.Verify(context.Background(), r); err != nil {
		t.Fatalf("subprotocol token: %v", err)
	}
	if _, err := v.Verify(context.Background(), httptest.NewRequest("GET", "/x", nil)); err != ErrNoToken {
		t.Fatalf("no token: %v", err)
	}
}

func TestIdentityFilesReadEveryTime(t *testing.T) {
	dir := t.TempDir()
	read := IdentityFiles(dir)
	if _, err := read(); err == nil {
		t.Fatal("missing identity accepted")
	}
	for k, v := range map[string]string{"atespace": "a5-eng\n", "name": "cc-1", "uid": "uid-1"} {
		os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644)
	}
	id, err := read()
	if err != nil || id != self {
		t.Fatalf("%+v %v", id, err)
	}
	os.WriteFile(filepath.Join(dir, "uid"), []byte("uid-9"), 0o644) // a fork
	if id, _ := read(); id.UID != "uid-9" {
		t.Fatal("identity cached")
	}
}

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(e string) { r.mu.Lock(); r.events = append(r.events, e); r.mu.Unlock() }
func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func testServer(t *testing.T, argv []string) (*Server, *recorder, signer) {
	t.Helper()
	v, ec, _ := testVerifier(t)
	cfg := kit.DefaultConfig()
	cfg.Relay.Connector = "claudecode"
	cfg.Relay.Interactive = argv
	cfg.Relay.Headless = []string{"sh", "-c", `echo "out:$0 mode:$DEFENSECLAW_ACTOR_MODE"; echo err >&2; exit 3`, "{prompt}"}
	rec := &recorder{}
	s := NewServer(Options{Config: cfg, Verifier: v,
		Warm: func(context.Context, string) error { rec.add("warm"); return nil },
	})
	t.Cleanup(func() {
		if s.agent != nil {
			s.agent.mu.Lock()
			if s.agent.cmd != nil && s.agent.running {
				_ = s.agent.cmd.Process.Kill()
			}
			s.agent.mu.Unlock()
		}
	})
	return s, rec, ec
}

// The golden-snapshot rule: a relay that has only served its wake-up probe
// has created nothing and asked for nothing.
func TestNothingStartsBeforeFirstAuthenticatedRequest(t *testing.T) {
	s, rec, ec := testServer(t, []string{"sh"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("readyz %v %v", resp, err)
	}
	resp, _ = http.Get(srv.URL + "/dcrelay/1/status")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status: %d", resp.StatusCode)
	}
	if s.session != "" || s.agent != nil || len(rec.list()) != 0 {
		t.Fatalf("state before the first authenticated request: session=%q agent=%v calls=%v", s.session, s.agent, rec.list())
	}
	req, _ := http.NewRequest("GET", srv.URL+"/dcrelay/1/status", nil)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("status %v %v", resp, err)
	}
	if s.session == "" {
		t.Fatal("no session after the first authenticated request")
	}
}

func needLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("actors are Linux")
	}
}

func dialWS(t *testing.T, url, token string, header http.Header) (*websocket.Conn, *http.Response, error) {
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}, HandshakeTimeout: 5 * time.Second}
	if header == nil {
		header = http.Header{}
	}
	if token != "" {
		header.Set("Authorization", "Bearer "+token)
	}
	return d.Dial("ws"+strings.TrimPrefix(url, "http")+"/dcrelay/1/ws?cols=100&rows=30", header)
}

func readUntil(t *testing.T, c *websocket.Conn, want string, ctl func(Control)) string {
	t.Helper()
	var screen strings.Builder
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.SetReadDeadline(deadline)
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v (screen %q)", err, screen.String())
		}
		ft, p, _ := Decode(msg)
		switch ft {
		case FrameData:
			screen.Write(p)
		case FrameControl:
			cc, _ := DecodeControl(p)
			if ctl != nil {
				ctl(cc)
			}
			if want == "ctl:"+cc.Type {
				return screen.String()
			}
		}
		if want != "" && strings.Contains(screen.String(), want) {
			return screen.String()
		}
	}
	t.Fatalf("never saw %q in %q", want, screen.String())
	return ""
}

func TestWebSocketSessionSurvivesReconnect(t *testing.T) {
	needLinux(t)
	s, rec, ec := testServer(t, []string{"sh", "-c", `while read l; do echo "got:$l cols:$(stty size | cut -d" " -f2)"; done`})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	if _, resp, err := dialWS(t, srv.URL, "", nil); err == nil || resp.StatusCode != 401 {
		t.Fatalf("unauthenticated websocket: %v", err)
	}
	tok := ec.token(t, claims(time.Now(), nil), TokenType)
	c, resp, err := dialWS(t, srv.URL, tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := resp.Header.Get("Sec-WebSocket-Protocol"); p != Subprotocol {
		t.Fatalf("subprotocol %q", p)
	}
	var hello Control
	readUntil(t, c, "ctl:hello", func(cc Control) {
		if cc.Type == CtlHello {
			hello = cc
		}
	})
	if hello.Version != Version || hello.Session == "" {
		t.Fatalf("hello %+v", hello)
	}
	if ev := rec.list(); len(ev) == 0 || ev[0] != "warm" {
		t.Fatalf("the gateway path was not pre-connected before the attachment: %v", ev)
	}
	c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("one\r")))
	readUntil(t, c, "got:one cols:100", nil)
	c.WriteMessage(websocket.BinaryMessage, Encode(FrameResize, []byte(`{"cols":132,"rows":40}`)))
	time.Sleep(200 * time.Millisecond)
	c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("two\r")))
	readUntil(t, c, "got:two cols:132", nil)
	c.WriteMessage(websocket.BinaryMessage, EncodeControl(Control{Type: CtlDetach}))
	c.Close()

	// A token opens one attachment.
	if _, resp, err := dialWS(t, srv.URL, tok, nil); err == nil || resp.StatusCode != 401 {
		t.Fatalf("a used token opened a second attachment: %v", err)
	}
	// A new token in a subprotocol works too and is never echoed.
	h := http.Header{}
	d := websocket.Dialer{Subprotocols: []string{Subprotocol, TokenProtocol + ec.token(t, claims(time.Now(), nil), TokenType)}}
	c2, resp, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/dcrelay/1/ws?cols=90&rows=30", h)
	if err != nil {
		t.Fatal(err)
	}
	if p := resp.Header.Get("Sec-WebSocket-Protocol"); p != Subprotocol {
		t.Fatalf("subprotocol echoed %q", p)
	}
	defer c2.Close()
	readUntil(t, c2, "ctl:hello", nil)
	c2.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("three\r")))
	out := readUntil(t, c2, "got:three", nil)
	if !strings.Contains(out, "got:one") {
		// The scrollback of the same session comes first.
		t.Fatalf("the session did not survive the reconnect: %q", out)
	}
	if !s.agent.Running() {
		t.Fatal("session gone")
	}
}

func TestAgentExitIsReported(t *testing.T) {
	needLinux(t)
	s, _, ec := testServer(t, []string{"sh", "-c", "read l; exit 7"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	c, _, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	readUntil(t, c, "ctl:hello", nil)
	c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("x\r")))
	var code *int
	readUntil(t, c, "ctl:exit", func(cc Control) {
		if cc.Type == CtlExit {
			code = cc.Code
		}
	})
	if code == nil {
		t.Fatal("no exit code")
	}
	if *code != 7 {
		t.Fatalf("exit code %d, want 7", *code)
	}
}

func TestLongPollFallback(t *testing.T) {
	needLinux(t)
	s, _, ec := testServer(t, []string{"sh", "-c", `while read l; do echo "lp:$l"; done`})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	tok := ec.token(t, claims(time.Now(), nil), TokenType)
	do := func(method, path string, body []byte, tk string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		if tk != "" {
			req.Header.Set("Authorization", "Bearer "+tk)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := do("POST", "/dcrelay/1/poll?cols=80&rows=24", nil, tok)
	var open struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&open)
	if open.ID == "" {
		t.Fatalf("open %d", resp.StatusCode)
	}
	// Another person cannot read it.
	other := ec.token(t, claims(time.Now(), func(c map[string]any) { c["sub"] = "bob@example.test" }), TokenType)
	if r := do("GET", "/dcrelay/1/poll/"+open.ID+"?cursor=0", nil, other); r.StatusCode != 404 {
		t.Fatalf("another person's read: %d", r.StatusCode)
	}
	in := AppendStream(nil, Encode(FrameData, []byte("hello\r")))
	if r := do("POST", "/dcrelay/1/poll/"+open.ID, in, tok); r.StatusCode != 204 {
		t.Fatalf("write %d", r.StatusCode)
	}
	cursor := "0"
	var screen strings.Builder
	sawHello := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(screen.String(), "lp:hello") {
		r := do("GET", "/dcrelay/1/poll/"+open.ID+"?cursor="+cursor, nil, tok)
		var b bytes.Buffer
		b.ReadFrom(r.Body)
		cursor = r.Header.Get("X-Dcrelay-Cursor")
		frames, err := SplitStream(b.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range frames {
			ft, p, _ := Decode(f)
			if ft == FrameData {
				screen.Write(p)
			}
			if ft == FrameControl && strings.Contains(string(p), `"hello"`) {
				sawHello = true
			}
		}
	}
	if !sawHello || !strings.Contains(screen.String(), "lp:hello") {
		t.Fatalf("hello %v screen %q", sawHello, screen.String())
	}
	if r := do("DELETE", "/dcrelay/1/poll/"+open.ID, nil, tok); r.StatusCode != 204 {
		t.Fatalf("delete %d", r.StatusCode)
	}
}

func TestHeadlessTaskIsUnattendedAndReportsExit(t *testing.T) {
	s, rec, ec := testServer(t, []string{"sh"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	taskTok := func(task string) string {
		return ec.token(t, claims(time.Now(), func(c map[string]any) { c["dc.task_sha256"] = TaskDigest(task) }), TokenType)
	}
	for name, tc := range map[string]struct{ tok, body string }{
		"another task text":   {taskTok("fix the bug"), `{"prompt":"rm -rf the repo"}`},
		"interactive session": {ec.token(t, claims(time.Now(), nil), TokenType), `{"prompt":"fix the bug"}`},
		"extra args":          {taskTok("fix the bug"), `{"prompt":"fix the bug","args":["--x"]}`},
	} {
		req, _ := http.NewRequest("POST", srv.URL+"/dcrelay/1/task", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+tc.tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode == http.StatusOK {
			t.Fatalf("%s: task started (%v)", name, err)
		}
	}
	req, _ := http.NewRequest("POST", srv.URL+"/dcrelay/1/task", strings.NewReader(`{"prompt":"fix the bug"}`))
	req.Header.Set("Authorization", "Bearer "+taskTok("fix the bug"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var events []TaskEvent
	dec := json.NewDecoder(resp.Body)
	for {
		var e TaskEvent
		if dec.Decode(&e) != nil {
			break
		}
		events = append(events, e)
	}
	var out, errs []string
	var code *int
	for _, e := range events {
		switch e.Type {
		case "stdout":
			out = append(out, e.Data)
		case "stderr":
			errs = append(errs, e.Data)
		case "exit":
			code = e.Code
		}
	}
	if len(out) != 1 || out[0] != "out:fix the bug mode:unattended" || len(errs) != 1 || code == nil || *code != 3 {
		t.Fatalf("events %+v", events)
	}
	if ev := rec.list(); len(ev) < 1 || ev[0] != "warm" {
		t.Fatalf("calls %v: the gateway path is warmed before the task runs", ev)
	}
	if _, err := expandHeadless([]string{"x"}, "p"); err == nil {
		t.Fatal("a headless command without {prompt} accepted")
	}
	if _, err := expandHeadless(nil, "p"); err == nil {
		t.Fatal("an interactive-only connector accepted a task")
	}
}

func TestAttachmentEndsWithItsToken(t *testing.T) {
	needLinux(t)
	s, _, ec := testServer(t, []string{"sh", "-c", "while read l; do echo $l; done"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	now := time.Now()
	tok := ec.token(t, claims(now, func(c map[string]any) { c["exp"] = now.Add(2 * time.Second).Unix() }), TokenType)
	// The verifier allows 60 s of skew; the relay itself ends the
	// attachment at the token's exp.
	c, _, err := dialWS(t, srv.URL, tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var msg string
	readUntil(t, c, "ctl:error", func(cc Control) {
		if cc.Type == CtlError {
			msg = cc.Message
		}
	})
	if msg != "session token expired" {
		t.Fatalf("message %q", msg)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := c.ReadMessage(); err != nil {
			break
		}
	}
	if !s.agent.Running() {
		t.Fatal("the agent stopped with the attachment")
	}
}

func TestLongPollAttachmentsAreCapped(t *testing.T) {
	needLinux(t)
	s, _, ec := testServer(t, []string{"sh", "-c", "while read l; do echo $l; done"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	open := func() int {
		req, _ := http.NewRequest("POST", srv.URL+"/dcrelay/1/poll", nil)
		req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < maxPollsPerPerson; i++ {
		if code := open(); code != 200 {
			t.Fatalf("open %d: %d", i, code)
		}
	}
	if code := open(); code != http.StatusTooManyRequests {
		t.Fatalf("over the cap: %d", code)
	}
}

func TestSessionKeysNeedAnIssuer(t *testing.T) {
	dir := t.TempDir()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	p := filepath.Join(dir, "k.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	cfg := kit.DefaultConfig()
	cfg.Relay.SessionKeys = map[string]string{"k1": p}
	if _, err := NewVerifier(cfg); err == nil {
		t.Fatal("session keys without an issuer accepted")
	}
	cfg.Relay.SessionIssuer = "https://defenseclaw-admin"
	if v, err := NewVerifier(cfg); err != nil || v == nil {
		t.Fatalf("%v %v", v, err)
	}
	v, ec1, _ := testVerifier(t)
	v.Issuer = ""
	if _, err := v.VerifyToken(ec1.token(t, claims(time.Now(), nil), TokenType)); err == nil {
		t.Fatal("a verifier without an issuer accepted a token")
	}
}

// The agent's user can neither trace the relay nor open its descriptors
// (the PTY master): the relay is not dumpable once hardened.
func TestRelayIsNotDumpable(t *testing.T) {
	needLinux(t)
	self, _ := os.Executable()
	out, err := exec.Command(self, "harden-probe").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "dumpable false <nil>" {
		t.Fatalf("probe: %q %v", out, err)
	}
	// The agent the relay starts is dumpable again (exec resets it).
	a := &Agent{Argv: []string{"sh", "-c", "grep -q . /proc/self/status && echo ok"}, Env: os.Environ()}
	at, err := a.Attach(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	for ev := range at.Events {
		got.Write(ev.data)
	}
	if !strings.Contains(got.String(), "ok") {
		t.Fatalf("agent output %q", got.String())
	}
}

// The client and the relay together, under -race (GAP-0088).
func TestClientAttachDetach(t *testing.T) {
	needLinux(t)
	s, _, ec := testServer(t, []string{"sh", "-c", "while read l; do echo got:$l; done"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	for _, lp := range []bool{false, true} {
		pr, pw := io.Pipe()
		var out syncBuffer
		go func() {
			time.Sleep(300 * time.Millisecond)
			pw.Write([]byte("hi\r"))
			for i := 0; i < 50 && !strings.Contains(out.String(), "got:hi"); i++ {
				time.Sleep(50 * time.Millisecond)
			}
			pw.Write([]byte{DetachKey})
		}()
		res, err := Attach(context.Background(), pr, &out, AttachOptions{BaseURL: srv.URL,
			Token: ec.token(t, claims(time.Now(), nil), TokenType), LongPoll: lp})
		if err != nil || !res.Detached || res.Session == "" || !strings.Contains(out.String(), "got:hi") {
			t.Fatalf("long-poll=%v: %+v %v %q", lp, res, err, out.String())
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
