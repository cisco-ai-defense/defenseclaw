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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const detachLine = "Detached. The agent keeps running. Come back with: defenseclaw substrate connect cc-1"

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
			r.router.mu.Lock()
			for _, tg := range r.router.targets {
				if tg != "a6-test/cc-1" {
					t.Errorf("ate-target-actor %q", tg)
				}
			}
			r.router.mu.Unlock()
			if n := r.sess.count(); n != 1 {
				t.Fatalf("session calls %d", n)
			}
			noSecrets(t, "stderr", errs)
		})
	}
}

func TestCertificateSources(t *testing.T) {
	r := newRig(t, nil)
	other := newPKI(t, "other-ca")
	badCert, badKey := other.issue(t, "intruder", false)
	goodCert, goodKey := r.sess.cert, r.sess.key
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	goodCertF, goodKeyF := write("good.pem", goodCert), write("good.key", goodKey)
	badCertF, badKeyF := write("bad.pem", badCert), write("bad.key", badKey)
	for _, tc := range []struct {
		name               string
		grantCert, grantKy []byte
		certF, keyF        string
		wantErr            string
	}{
		{name: "grant", grantCert: goodCert, grantKy: goodKey},
		{name: "files", certF: goodCertF, keyF: goodKeyF},
		{name: "grant wins over files", grantCert: goodCert, grantKy: goodKey, certF: badCertF, keyF: badKeyF},
		{name: "wrong CA", grantCert: badCert, grantKy: badKey, wantErr: "the router refused the client certificate"},
		{name: "wrong CA files", certF: badCertF, keyF: badKeyF, wantErr: "the router refused the client certificate"},
		{name: "no certificate", wantErr: "the router refused the client certificate"},
		{name: "half a grant", grantCert: goodCert, wantErr: "half a client certificate"},
		{name: "half the files", certF: goodCertF, wantErr: "both a certificate file and a key file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r.sess.cert, r.sess.key = tc.grantCert, tc.grantKy
			o := r.options()
			o.Router.CertFile, o.Router.KeyFile = tc.certF, tc.keyF
			m, err := Status(context.Background(), o)
			if tc.wantErr == "" {
				if err != nil || m["version"] != relay.Version {
					t.Fatalf("status %v %v", m, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v, want %q", err, tc.wantErr)
			}
			noSecrets(t, "error", err.Error())
		})
	}
}

func TestRouterRefusals(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{403, "the cluster refused this connection (not allowed to reach this actor)"},
		{401, "not allowed to reach this actor"},
		{404, "no such running actor: a6-test/cc-1"},
		{418, "the router answered 418"},
		{502, "the router answered 502"},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			r := newRig(t, nil)
			r.router.statusFor = func(int) (int, http.Header) { return tc.status, nil }
			got := r.wait(r.start(r.options()))
			if tc.status == 502 {
				// A server error is retried, then reported.
				if got.err == nil || !strings.Contains(got.err.Error(), tc.want) || !strings.Contains(got.err.Error(), "defenseclaw substrate connect cc-1") {
					t.Fatalf("error %v", got.err)
				}
				return
			}
			if got.err == nil || !strings.Contains(got.err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", got.err, tc.want)
			}
			if n := r.router.count(); n != 1 {
				t.Fatalf("a refusal was retried: %d CONNECTs", n)
			}
			noSecrets(t, "error", got.err.Error())
		})
	}
}

func TestParkingThenRoom(t *testing.T) {
	r := newRig(t, nil)
	r.router.statusFor = func(n int) (int, http.Header) {
		switch n {
		case 1:
			return 503, http.Header{"Retry-After": {"3"}}
		case 2:
			return 503, nil
		}
		return 200, nil
	}
	run := r.start(r.options())
	waitFor(t, "screen", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if n := strings.Count(r.errb.String(), fullMsg); n != 1 {
		t.Fatalf("cluster-full message %d times: %q", n, r.errb.String())
	}
	sl := r.clock.slept()
	if len(sl) != 2 || sl[0] < 3*time.Second {
		t.Fatalf("sleeps %v (Retry-After 3 not honoured)", sl)
	}
}

func TestParkingGivesUpAfterMaxWait(t *testing.T) {
	r := newRig(t, nil)
	r.router.statusFor = func(int) (int, http.Header) { return 503, nil }
	o := r.options()
	o.Now = r.clock.now
	o.MaxWait = 5 * time.Second
	o.Backoff = Backoff{Initial: time.Second, Max: 2 * time.Second, Jitter: -1}
	got := r.wait(r.start(o))
	want := "no room in the cluster after 5s; try again later or ask your administrator to raise the pool"
	if got.err == nil || got.err.Error() != want {
		t.Fatalf("error %v", got.err)
	}
	var total time.Duration
	for _, d := range r.clock.slept() {
		total += d
	}
	if total != 5*time.Second {
		t.Fatalf("waited %v", total)
	}
	if fmtDur(10*time.Minute) != "10m" {
		t.Fatalf("default MaxWait shows as %q", fmtDur(10*time.Minute))
	}
	noSecrets(t, "error", got.err.Error())
}

func TestParkingInsideTunnel(t *testing.T) {
	// The relay (or the router's ingress inside the tunnel) answering 503 is
	// the same wait.
	r := newRig(t, nil)
	r.relay.blockWS = 503
	o := r.options()
	o.Transport = TransportWebSocket
	run := r.start(o)
	waitFor(t, "full message", func() bool { return strings.Contains(r.errb.String(), fullMsg) })
	r.relay.mu.Lock()
	r.relay.blockWS = 0
	r.relay.mu.Unlock()
	waitFor(t, "screen", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("\x1d")
	if got := r.wait(run); got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
}

func TestReconnectAfterDrop(t *testing.T) {
	for _, tc := range []struct {
		name  string
		life  time.Duration
		calls int
	}{
		{"token valid", 10 * time.Minute, 1},
		{"token near expiry", 30 * time.Second, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			r.sess.life = tc.life
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
			if n := r.sess.count(); n != tc.calls {
				t.Fatalf("session calls %d, want %d", n, tc.calls)
			}
		})
	}
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
	for _, status := range []int{426, 400, 403, 502} {
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
		})
	}
}

func TestSessionRefusedIsNotRetried(t *testing.T) {
	r := newRig(t, nil)
	r.sess.err = fmt.Errorf("admin listener: %w", ErrSessionRefused)
	got := r.wait(r.start(r.options()))
	if got.err == nil || !strings.Contains(got.err.Error(), "not allowed") || r.sess.count() != 1 || r.router.count() != 0 {
		t.Fatalf("err %v calls %d connects %d", got.err, r.sess.count(), r.router.count())
	}
}

func TestRelayRefusesTokenTwice(t *testing.T) {
	r := newRig(t, nil)
	r.relay.tokens = map[string]bool{}
	got := r.wait(r.start(r.options()))
	if got.err == nil || !strings.Contains(got.err.Error(), "refused the session token") {
		t.Fatalf("error %v", got.err)
	}
	if n := r.sess.count(); n != 2 {
		t.Fatalf("a refused token was not renewed once: %d session calls", n)
	}
	noSecrets(t, "error", got.err.Error())
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

func TestSessionCacheRefresh(t *testing.T) {
	clock := newFakeClock()
	src := &fakeSessions{now: clock.now, life: 2 * time.Minute}
	c := &sessionCache{src: src, t: testTarget, now: clock.now}
	ctx := context.Background()
	for i, step := range []struct {
		advance time.Duration
		force   bool
		calls   int
	}{
		{0, false, 1},                // none yet
		{30 * time.Second, false, 1}, // 90 s left
		{31 * time.Second, false, 2}, // 59 s left: renewed
		{0, true, 3},                 // forced
	} {
		clock.sleep(ctx, step.advance)
		if _, err := c.get(ctx, step.force); err != nil {
			t.Fatal(err)
		}
		if src.count() != step.calls {
			t.Fatalf("step %d: %d calls, want %d", i, src.count(), step.calls)
		}
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

func TestTunnelSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Router
		tg   Target
		want string
	}{
		{"http URL", Router{URL: "http://" + testRouterAddr}, testTarget, "https://HOST:PORT"},
		{"no host", Router{URL: "https://"}, testTarget, "https://HOST:PORT"},
		{"bad port", Router{URL: "https://" + testRouterAddr, RelayPort: 70000}, testTarget, "not a TCP port"},
		{"header injection", Router{URL: "https://" + testRouterAddr}, Target{Atespace: "a", Name: "b\r\nx: y"}, "not valid"},
		{"missing CA", Router{URL: "https://" + testRouterAddr, CAFile: "/nonexistent/ca.pem"}, testTarget, "router CA file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTunnel(context.Background(), tc.r, SessionGrant{Token: testToken}, tc.tg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
			noSecrets(t, "error", err.Error())
		})
	}
	tu, err := NewTunnel(context.Background(), Router{URL: "https://" + testRouterAddr}, SessionGrant{}, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer tu.Close()
	if tu.BaseURL() != "http://actor.invalid:8080" || tu.HTTPClient() == nil || tu.Dialer() == nil {
		t.Fatalf("tunnel %q", tu.BaseURL())
	}
	if _, err := tu.DialContext(context.Background(), "tcp", "example.test:80"); err == nil {
		t.Fatal("the tunnel dialed somewhere other than the actor")
	}
}

func TestTunnelThroughProxy(t *testing.T) {
	r := newRig(t, nil)
	routerAddr := r.router.ln.Addr().String()
	pl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()
	seen := make(chan string, 4)
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
				seen <- req.Method + " " + req.Host + " auth=" + fmt.Sprint(req.Header.Get("Proxy-Authorization") != "")
				up, err := net.Dial("tcp", routerAddr)
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
	o.Router.proxy = func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: "proxy.example.test:3128", User: url.UserPassword("u", "p")}, nil
	}
	o.Router.dial = func(ctx context.Context, network, a string) (net.Conn, error) {
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
	if s := <-seen; s != "CONNECT "+testRouterAddr+" auth=true" {
		t.Fatalf("proxy saw %q", s)
	}
}

func TestErrorsNameNoSecrets(t *testing.T) {
	// Every refusal path above checks its own text; this checks the
	// wrapped forms too.
	for _, err := range []error{
		&TunnelError{Status: 503, Kind: ErrClusterFull},
		&TunnelError{Kind: ErrCertRefused},
		tokenRefused(testTarget),
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
