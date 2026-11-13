// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const detachLine = "Detached. The agent keeps running. Come back with: defenseclaw substrate connect cc-1"

// distinctBearers fails unless every request carried a person bearer of its
// own (a fresh one from the source each time).
func distinctBearers(t *testing.T, reqs []seen) {
	t.Helper()
	got := map[string]bool{}
	for _, s := range reqs {
		if !strings.HasPrefix(s.bearer, bearerPrefix) || got[s.bearer] {
			t.Fatalf("request %s %s: bearer reused or missing (%d requests)", s.method, s.path, len(reqs))
		}
		got[s.bearer] = true
	}
}

func TestAttachTransports(t *testing.T) {
	for _, tc := range []struct {
		transport, action string
	}{
		{TransportWebSocket, "detach"},
		{TransportWebSocket, "exit"},
		{TransportLongPoll, "detach"},
		{TransportLongPoll, "exit"},
		{TransportAuto, "detach"},
	} {
		t.Run(tc.transport+"/"+tc.action, func(t *testing.T) {
			r := newRig(t, nil)
			o := r.options()
			o.Transport = tc.transport
			run := r.start(o)
			screen := "screen:1"
			if tc.transport == TransportLongPoll {
				screen = "screen:lp"
			}
			waitFor(t, screen, func() bool { return strings.Contains(r.out.String(), screen) })
			r.sizes <- relay.Resize{Cols: 120, Rows: 40}
			waitFor(t, "resize frame", func() bool {
				_, _, _, rs := r.relay.snapshot()
				for _, x := range rs {
					if x == (relay.Resize{Cols: 120, Rows: 40}) {
						return true
					}
				}
				return false
			})
			r.typ("hello\r")
			waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:hello") })
			if tc.action == "detach" {
				r.typ("x\x1d")
			} else {
				r.typ("EXIT\r")
			}
			got := r.wait(run)
			if got.err != nil {
				t.Fatalf("Attach: %v", got.err)
			}
			want := tc.transport
			if want == TransportAuto {
				want = TransportWebSocket
			}
			if got.res.Transport != want || got.res.Session != "sess-1" || got.res.Reconnects != 0 {
				t.Fatalf("result %+v", got.res)
			}
			errs := r.errb.String()
			if !strings.Contains(errs, "Ctrl-] detaches") || !strings.Contains(errs, "a6-test/cc-1") {
				t.Fatalf("no banner: %q", errs)
			}
			switch tc.action {
			case "detach":
				if !got.res.Detached || got.res.ExitCode != nil || !strings.Contains(errs, detachLine) {
					t.Fatalf("detach: %+v %q", got.res, errs)
				}
				waitFor(t, "relay saw the detach", func() bool { _, _, d, _ := r.relay.snapshot(); return d == 1 })
			case "exit":
				if got.res.Detached || got.res.ExitCode == nil || *got.res.ExitCode != 7 {
					t.Fatalf("exit: %+v", got.res)
				}
			}
			reqs := r.admin.seen()
			if tc.transport == TransportLongPoll && len(reqs) < 3 {
				t.Fatalf("long-poll made %d requests", len(reqs))
			}
			if tc.transport != TransportLongPoll && r.admin.count(isWS) != 1 {
				t.Fatalf("%d WebSocket handshakes", r.admin.count(isWS))
			}
			distinctBearers(t, reqs)
			noSecrets(t, "stderr", errs)
		})
	}
}

func TestRouteRefusals(t *testing.T) {
	for _, tc := range []struct {
		status int
		kind   error
		want   string
	}{
		{401, ErrNotSignedIn, "run: defenseclaw substrate login"},
		{403, ErrNotAllowed, "you are not allowed to attach to a6-test/cc-1"},
		{404, ErrNoActor, "no agent a6-test/cc-1 of yours in this cluster"},
		{501, ErrNotOffered, "this cluster does not offer attach through the gateway yet; ask your administrator to upgrade DefenseClaw"},
	} {
		for _, transport := range []string{TransportAuto, TransportWebSocket, TransportLongPoll} {
			t.Run(fmt.Sprint(tc.status, "/", transport), func(t *testing.T) {
				r := newRig(t, nil)
				r.admin.setAnswer(func(*http.Request) (int, http.Header) { return tc.status, nil })
				o := r.options()
				o.Transport = transport
				got := r.wait(r.start(o))
				if got.err == nil || !strings.Contains(got.err.Error(), tc.want) || !errors.Is(got.err, tc.kind) {
					t.Fatalf("error %v, want %q", got.err, tc.want)
				}
				// One try: the handshake and the probe that reads the
				// gateway's answer, or the long-poll open.
				want := 2
				if transport == TransportLongPoll {
					want = 1
				}
				if n := r.admin.count(nil); n != want {
					t.Fatalf("a refusal was retried: %d requests", n)
				}
				noSecrets(t, "error", got.err.Error())
				noSecrets(t, "stderr", r.errb.String())
			})
		}
	}
}

func TestNotSignedInBearer(t *testing.T) {
	// The bearer was refused by the gateway because it is not one.
	r := newRig(t, nil)
	o := r.options()
	o.Bearer = func(context.Context) (string, error) { return "not-a-bearer", nil }
	got := r.wait(r.start(o))
	if got.err == nil || !errors.Is(got.err, ErrNotSignedIn) {
		t.Fatalf("error %v", got.err)
	}
	// The source cannot give a sign-in: final, nothing sent, the source's
	// error kept for errors.Is.
	sentinel := errors.New("you are not signed in; run: defenseclaw substrate login")
	r = newRig(t, nil)
	r.bearer.err = fmt.Errorf("the sign-in expired: %w", sentinel)
	got = r.wait(r.start(r.options()))
	if got.err == nil || !errors.Is(got.err, sentinel) || r.admin.count(nil) != 0 || r.bearer.count() != 1 {
		t.Fatalf("error %v, %d requests, %d bearer calls", got.err, r.admin.count(nil), r.bearer.count())
	}
	if _, err := Status(context.Background(), r.options()); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("status: %v", err)
	}
	// An issuer that cannot be reached is retried.
	r = newRig(t, nil)
	r.bearer.err = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	o = r.options()
	o.Backoff.MaxAttempts = 3
	got = r.wait(r.start(o))
	if got.err == nil || !strings.Contains(got.err.Error(), "after 3 tries") || !strings.Contains(got.err.Error(), "could not refresh your sign-in") {
		t.Fatalf("error %v", got.err)
	}
}

// failFirst answers status (with hdr on the first) to the first n
// WebSocket handshakes and to the probes that follow them.
func failFirst(n, status int, first http.Header) func(*http.Request) (int, http.Header) {
	var mu sync.Mutex
	ws := 0
	return func(r *http.Request) (int, http.Header) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/attach/ws") {
			ws++
		}
		switch {
		case ws == 1:
			return status, first
		case ws <= n:
			return status, nil
		}
		return 0, nil
	}
}

func TestWaitThenUp(t *testing.T) {
	for _, tc := range []struct {
		status    int
		msg, gone string
	}{
		{503, fullMsg, startingMsg},
		{429, fullMsg, startingMsg},
		{502, startingMsg, fullMsg},
		{504, startingMsg, fullMsg},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			r := newRig(t, nil)
			r.admin.setAnswer(failFirst(2, tc.status, http.Header{"Retry-After": {"3"}}))
			run := r.start(r.options())
			waitFor(t, "screen", func() bool { return strings.Contains(r.out.String(), "screen:1") })
			r.typ("\x1d")
			got := r.wait(run)
			if got.err != nil || !got.res.Detached || got.res.Transport != TransportWebSocket {
				t.Fatalf("%+v %v", got.res, got.err)
			}
			errs := r.errb.String()
			if strings.Count(errs, tc.msg) != 1 || strings.Contains(errs, tc.gone) {
				t.Fatalf("messages: %q", errs)
			}
			sl := r.clock.slept()
			if len(sl) != 2 || sl[0] < 3*time.Second {
				t.Fatalf("sleeps %v (Retry-After 3 not honoured)", sl)
			}
		})
	}
}

func TestWaitGivesUpAfterMaxWait(t *testing.T) {
	for _, tc := range []struct {
		status    int
		transport string
		want      string
	}{
		{503, TransportAuto, "no room in the cluster after 5s; try again later or ask your administrator to raise the pool"},
		{503, TransportLongPoll, "no room in the cluster after 5s; try again later or ask your administrator to raise the pool"},
		{502, TransportAuto, "the agent cc-1 did not start within 5s; check it with: defenseclaw substrate status cc-1"},
		{504, TransportLongPoll, "the agent cc-1 did not start within 5s; check it with: defenseclaw substrate status cc-1"},
	} {
		t.Run(fmt.Sprint(tc.status, "/", tc.transport), func(t *testing.T) {
			r := newRig(t, nil)
			r.admin.setAnswer(func(*http.Request) (int, http.Header) { return tc.status, nil })
			o := r.options()
			o.Transport = tc.transport
			o.Now = r.clock.now
			o.MaxWait = 5 * time.Second
			o.Backoff = Backoff{Initial: time.Second, Max: 2 * time.Second, Jitter: -1}
			got := r.wait(r.start(o))
			if got.err == nil || got.err.Error() != tc.want {
				t.Fatalf("error %v", got.err)
			}
			var total time.Duration
			for _, d := range r.clock.slept() {
				total += d
			}
			if total != 5*time.Second {
				t.Fatalf("waited %v", total)
			}
			noSecrets(t, "error", got.err.Error())
		})
	}
	if fmtDur(10*time.Minute) != "10m" {
		t.Fatalf("default MaxWait shows as %q", fmtDur(10*time.Minute))
	}
}

func TestReconnectAfterDrop(t *testing.T) {
	r := newRig(t, nil)
	run := r.start(r.options())
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("DROP\r")
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	r.typ("after\r")
	waitFor(t, "echo on the new connection", func() bool { return strings.Contains(r.out.String(), "echo:after") })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached || got.res.Reconnects != 1 || got.res.Session != "sess-1" {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if !strings.Contains(r.errb.String(), lostMsg) {
		t.Fatalf("no reconnect message: %q", r.errb.String())
	}
	if n := r.admin.count(isWS); n != 2 {
		t.Fatalf("%d handshakes", n)
	}
	distinctBearers(t, r.admin.seen())
}

func TestGiveUpAfterMaxAttempts(t *testing.T) {
	r := newRig(t, nil)
	r.relay.blockWS = 426
	o := r.options()
	o.Transport = TransportWebSocket // forced: no fallback
	o.Backoff.MaxAttempts = 3
	got := r.wait(r.start(o))
	if got.err == nil || !strings.Contains(got.err.Error(), "after 3 tries") || !strings.Contains(got.err.Error(), "defenseclaw substrate connect cc-1") {
		t.Fatalf("error %v", got.err)
	}
	if ws, polls, _, _ := r.relay.snapshot(); ws != 0 || polls != 0 {
		t.Fatalf("forced websocket fell back: ws %d polls %d", ws, polls)
	}
	noSecrets(t, "error", got.err.Error())
	noSecrets(t, "stderr", r.errb.String())
}

func TestLongPollFallback(t *testing.T) {
	// Something between the launcher and the relay refuses the upgrade while
	// plain requests get through.
	for _, status := range []int{426, 400, 403, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			r := newRig(t, nil)
			r.relay.blockWS = status
			run := r.start(r.options())
			waitFor(t, "long-poll screen", func() bool { return strings.Contains(r.out.String(), "screen:lp") })
			r.typ("hi\r")
			waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:hi") })
			r.typ("\x1d")
			got := r.wait(run)
			if got.err != nil || !got.res.Detached || got.res.Transport != TransportLongPoll {
				t.Fatalf("%+v %v", got.res, got.err)
			}
			if n := strings.Count(r.errb.String(), fallbackMsg); n != 1 {
				t.Fatalf("fallback message %d times: %q", n, r.errb.String())
			}
			if strings.Contains(r.errb.String(), fullMsg) || strings.Contains(r.errb.String(), startingMsg) {
				t.Fatalf("a refused upgrade was taken for the gateway's answer: %q", r.errb.String())
			}
		})
	}
}

func TestInputEndDetaches(t *testing.T) {
	r := newRig(t, nil)
	run := r.start(r.options())
	waitFor(t, "screen", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.inW.Close()
	got := r.wait(run)
	if got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
}

func TestBackoffDefaultsAndBounds(t *testing.T) {
	b := Backoff{}.withDefaults()
	if b.Initial != 500*time.Millisecond || b.Max != 10*time.Second || b.Factor != 2 || b.Jitter != 0.3 || b.MaxAttempts != 12 {
		t.Fatalf("defaults %+v", b)
	}
	r := newRetry(Backoff{})
	for i := 0; i < 20; i++ {
		d := r.next()
		if d < 350*time.Millisecond || d > 13*time.Second {
			t.Fatalf("delay %d = %v out of bounds", i, d)
		}
	}
	r = newRetry(Backoff{Initial: time.Second, Max: 4 * time.Second, Jitter: -1})
	var got []time.Duration
	for i := 0; i < 4; i++ {
		got = append(got, r.next())
	}
	if fmt.Sprint(got) != "[1s 2s 4s 4s]" {
		t.Fatalf("delays %v", got)
	}
}

func TestAttachPrefix(t *testing.T) {
	for _, tc := range []struct {
		admin string
		tg    Target
		want  string
	}{
		{"https://" + testAdminAddr, testTarget, "https://" + testAdminAddr + testPrefixPath},
		{"https://" + testAdminAddr + "/", testTarget, "https://" + testAdminAddr + testPrefixPath},
		{" https://" + testAdminHost + "/gw/ ", testTarget, "https://" + testAdminHost + "/gw" + testPrefixPath},
		{"https://" + testAdminAddr, Target{Atespace: "a%b", Name: "c?d"}, "https://" + testAdminAddr + "/api/v1/substrate/actors/a%25b/c%3Fd/attach"},
	} {
		got, err := AttachPrefix(tc.admin, tc.tg)
		if err != nil || got != tc.want {
			t.Errorf("AttachPrefix(%q, %v) = %q, %v; want %q", tc.admin, tc.tg, got, err, tc.want)
		}
	}
}

func TestTunnelSettings(t *testing.T) {
	bearer := (&fakeBearer{}).token
	for _, tc := range []struct {
		name string
		g    Gateway
		b    BearerFunc
		tg   Target
		want string
	}{
		{"http URL", Gateway{BaseURL: "http://" + testAdminAddr}, bearer, testTarget, "https://HOST:PORT"},
		{"no host", Gateway{BaseURL: "https://"}, bearer, testTarget, "https://HOST:PORT"},
		{"query", Gateway{BaseURL: "https://" + testAdminAddr + "?x=1"}, bearer, testTarget, "https://HOST:PORT"},
		{"user info", Gateway{BaseURL: "https://u:p@" + testAdminAddr}, bearer, testTarget, "https://HOST:PORT"},
		{"slash in name", Gateway{BaseURL: "https://" + testAdminAddr}, bearer, Target{Atespace: "a", Name: "b/c"}, "not valid"},
		{"dot dot", Gateway{BaseURL: "https://" + testAdminAddr}, bearer, Target{Atespace: "..", Name: "b"}, "not valid"},
		{"header injection", Gateway{BaseURL: "https://" + testAdminAddr}, bearer, Target{Atespace: "a", Name: "b\r\nx: y"}, "not valid"},
		{"no actor", Gateway{BaseURL: "https://" + testAdminAddr}, bearer, Target{Name: "b"}, "atespace/name"},
		{"missing CA", Gateway{BaseURL: "https://" + testAdminAddr, CAFile: "/nonexistent/ca.pem"}, bearer, testTarget, "admin CA file"},
		{"no bearer", Gateway{BaseURL: "https://" + testAdminAddr}, nil, testTarget, "defenseclaw substrate login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTunnel(context.Background(), tc.g, tc.b, tc.tg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
			noSecrets(t, "error", err.Error())
		})
	}
	tu, err := NewTunnel(context.Background(), Gateway{BaseURL: "https://" + testAdminAddr}, bearer, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer tu.Close()
	if tu.BaseURL() != "https://"+testAdminAddr+testPrefixPath || tu.HTTPClient() == nil || tu.Dialer() == nil {
		t.Fatalf("tunnel %q", tu.BaseURL())
	}
	// The bearer never goes to another host.
	for _, u := range []string{"https://example.test/x", "http://" + testAdminAddr + "/x"} {
		if _, err := tu.HTTPClient().Get(u); err == nil || !strings.Contains(err.Error(), "reaches only the admin listener") {
			t.Fatalf("%s: %v", u, err)
		}
	}
}

func TestUntrustedCertificate(t *testing.T) {
	r := newRig(t, nil)
	other := newPKI(t, "other-ca")
	otherFile := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherFile, other.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	o := r.options()
	o.Gateway.CAFile = otherFile
	if _, err := Status(context.Background(), o); err == nil || !strings.Contains(err.Error(), "not trusted here") {
		t.Fatalf("status: %v", err)
	}
	for _, transport := range []string{TransportAuto, TransportLongPoll} {
		o.Transport = transport
		got := r.wait(r.start(o))
		if got.err == nil || !strings.Contains(got.err.Error(), "the admin listener's certificate is not trusted here (set the admin CA file of this context)") {
			t.Fatalf("%s: %v", transport, got.err)
		}
		noSecrets(t, "error", got.err.Error())
	}
	if n := len(r.clock.slept()); n != 0 {
		t.Fatalf("an untrusted certificate was retried (%d sleeps)", n)
	}
}

func TestThroughProxy(t *testing.T) {
	r := newRig(t, nil)
	adminAddr := r.admin.srv.Listener.Addr().String()
	pl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()
	seenCh := make(chan string, 8)
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufioReader(c))
				if err != nil {
					return
				}
				seenCh <- req.Method + " " + req.Host + " auth=" + fmt.Sprint(req.Header.Get("Proxy-Authorization") != "")
				up, err := net.Dial("tcp", adminAddr)
				if err != nil {
					return
				}
				defer up.Close()
				c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				go copyConn(up, c)
				copyConn(c, up)
			}(c)
		}
	}()
	o := r.options()
	o.Gateway.proxy = func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: "proxy.example.test:3128", User: url.UserPassword("u", "p")}, nil
	}
	o.Gateway.dial = func(ctx context.Context, network, a string) (net.Conn, error) {
		if a != "proxy.example.test:3128" {
			return nil, fmt.Errorf("dialed %s, not the proxy", a)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, pl.Addr().String())
	}
	m, err := Status(context.Background(), o)
	if err != nil || m["version"] != relay.Version {
		t.Fatalf("status through the proxy: %v %v", m, err)
	}
	if s := <-seenCh; s != "CONNECT "+testAdminAddr+" auth=true" {
		t.Fatalf("proxy saw %q", s)
	}
	// The WebSocket goes through the proxy too.
	o.Transport = TransportWebSocket
	run := r.start(o)
	waitFor(t, "screen", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("\x1d")
	if got := r.wait(run); got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if s := <-seenCh; s != "CONNECT "+testAdminAddr+" auth=true" {
		t.Fatalf("proxy saw %q", s)
	}
}

func TestErrorsNameNoSecrets(t *testing.T) {
	// Every refusal path above checks its own text; this checks the
	// remaining forms.
	for _, err := range []error{
		&RouteError{Status: 503, Kind: ErrClusterFull},
		&RouteError{Status: 502, Kind: ErrStarting, Target: testTarget},
		&RouteError{Status: 418, Target: testTarget},
		&bearerError{errors.New("you are not signed in")},
		giveUp(testTarget, true, 12, errors.New("relay refused the attachment (status 502)")),
	} {
		noSecrets(t, "error", err.Error())
	}
}

func bufioReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

func copyConn(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	dst.Close()
}
