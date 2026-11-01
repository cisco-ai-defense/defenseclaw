// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// peerListener accepts on a free loopback port and counts the bytes any
// connection sends it. closeAtOnce closes every accepted connection at once.
type peerListener struct {
	ln       net.Listener
	received atomic.Int64
}

func newPeerListener(t *testing.T, addr string, closeAtOnce bool) *peerListener {
	t.Helper()
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	p := &peerListener{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if closeAtOnce {
				_ = conn.Close()
				continue
			}
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, _ := io.Copy(io.Discard, conn)
				p.received.Add(n)
			}()
		}
	}()
	return p
}

func (p *peerListener) addr() string { return p.ln.Addr().String() }

// verifiedTestClient is the per-user hook transport with its owner check
// replaced by verify.
func verifiedTestClient(addr string, verify func(net.Conn) error) *http.Client {
	dialer := &net.Dialer{Timeout: time.Second}
	return verifiedPerUserHTTPClient(defaultHookRequestTimeout, addr,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}, verify)
}

// A listener the per-user transport refused is never a gateway outage in
// the native hook (hookexec.Run), the hook of every Windows connector and of
// the legacy Linux native command (T12b round d). Before, the restart loop
// retried a refusal whose check error was restart-shaped and the outlasted
// and cold-start branches marked the call an outage, so the default
// (outage-open) tier let it run: a foreign listener that refused, one that
// accepted and closed at once while the Windows owner check waited past the
// connect deadline, and one that vanished after the refusal.
func TestPerUserNativeHookDeniesAnUnprovenListenerInTheOutageOpenTier(t *testing.T) {
	fastRestartRetries(t)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	type scenario struct {
		name string
		// setup returns the client and the listener whose bytes must stay 0.
		setup func(t *testing.T, opts *Options) *peerListener
	}
	refusing := func(checkErr error) func(t *testing.T, opts *Options) *peerListener {
		return func(t *testing.T, opts *Options) *peerListener {
			peer := newPeerListener(t, "127.0.0.1:0", false)
			opts.APIAddr = peer.addr()
			opts.HTTPClient = verifiedTestClient(peer.addr(), func(net.Conn) error { return checkErr })
			return peer
		}
	}
	scenarios := []scenario{
		{"foreign owner", refusing(errors.New("connected listener belongs to another account"))},
		{"owner process gone", refusing(&os.PathError{Op: "open", Path: "/proc/4242/status", Err: syscall.ENOENT})},
		{"socket row gone", refusing(io.EOF)},
		{"listener reset", refusing(fmt.Errorf("read: %w", syscall.ECONNRESET))},
		{"listener unbound during the check", refusing(fmt.Errorf("probe: %w", syscall.ECONNREFUSED))},
		{"check error at the restart deadline", refusing(fmt.Errorf("%w: owner check", errGatewayNotConnected))},
		{"accepts and closes at once, owner check past the connect deadline", func(t *testing.T, opts *Options) *peerListener {
			// The Windows tuple wait: the accepted row left the table, so
			// the check waits its own 3 s, past the try's connect deadline.
			peer := newPeerListener(t, "127.0.0.1:0", true)
			opts.APIAddr = peer.addr()
			opts.HTTPClient = verifiedTestClient(peer.addr(), func(net.Conn) error {
				select {
				case <-time.After(gatewayRestartBudget + 300*time.Millisecond):
				case <-stop:
				}
				return errors.New("connected gateway server socket was not found")
			})
			return peer
		}},
		{"vanishes after the refusal", func(t *testing.T, opts *Options) *peerListener {
			// Refused while bound, then the port is free: every later try is
			// a refused connection, which alone would be an outage.
			peer := newPeerListener(t, "127.0.0.1:0", false)
			opts.APIAddr = peer.addr()
			opts.HTTPClient = verifiedTestClient(peer.addr(), func(net.Conn) error {
				_ = peer.ln.Close()
				return io.EOF
			})
			return peer
		}},
		{"vanishes after the refusal, the cold start fails", func(t *testing.T, opts *Options) *peerListener {
			peer := newPeerListener(t, "127.0.0.1:0", false)
			opts.APIAddr = peer.addr()
			opts.HTTPClient = verifiedTestClient(peer.addr(), func(net.Conn) error {
				_ = peer.ln.Close()
				return &os.PathError{Op: "open", Path: "/proc/4242/status", Err: syscall.ENOENT}
			})
			opts.GatewayRecovery = func(context.Context, error) error { return errors.New("gateway start failed") }
			return peer
		}},
		{"binds while this account's gateway starts", func(t *testing.T, opts *Options) *peerListener {
			// The port is free on the first try; another account binds it
			// while the cold start runs, and that start then fails.
			free := newPeerListener(t, "127.0.0.1:0", false)
			addr := free.addr()
			_ = free.ln.Close()
			var peer atomic.Pointer[peerListener]
			opts.APIAddr = addr
			opts.HTTPClient = verifiedTestClient(addr, func(net.Conn) error { return io.EOF })
			opts.GatewayRecovery = func(context.Context, error) error {
				peer.Store(newPeerListener(t, addr, false))
				time.Sleep(200 * time.Millisecond)
				return errors.New("gateway start failed")
			}
			t.Cleanup(func() {
				if p := peer.Load(); p != nil && p.received.Load() != 0 {
					t.Errorf("the listener that bound during the start received %d bytes", p.received.Load())
				}
			})
			return free
		}},
	}
	events := map[string]struct{ event, stdin string }{
		"claudecode": {"PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`},
		"codex":      {"PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`},
		"cursor":     {"beforeShellExecution", `{"hook_event_name":"beforeShellExecution","command":"echo hi"}`},
		"hermes":     {"pre_tool_call", `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo hi"}}`},
	}
	for connector, call := range events {
		for _, sc := range scenarios {
			t.Run(connector+"/"+sc.name, func(t *testing.T) {
				var peer *peerListener
				result := run(t, connector, nil, func(opts *Options) {
					opts.Event = call.event
					opts.Stdin = strings.NewReader(call.stdin)
					opts.FailMode = "closed"
					opts.OutageFailModeNow = func() string { return "open" }
					opts.StartedAt = time.Now()
					peer = sc.setup(t, opts)
				})
				if !nativeOutageBlocked(result) {
					t.Fatalf("an unproven listener let the call run as an outage: code=%d stdout=%q stderr=%q",
						result.code, result.stdout, result.stderr)
				}
				out := result.stdout + result.stderr
				if strings.Contains(out, "fail mode open for an outage") {
					t.Fatalf("an unproven listener was reported as an outage: %q", out)
				}
				if !strings.Contains(out, foreignListenerReasonPrefix) {
					t.Fatalf("the deny does not name the listener: %q", out)
				}
				if n := peer.received.Load(); n != 0 {
					t.Fatalf("the unproven listener received %d bytes", n)
				}
			})
		}
	}
}

// The controls: this account's gateway still answers through the same
// transport, and a port nobody listens on is still an outage.
func TestPerUserNativeHookOutageStillOpensForThisAccountsGateway(t *testing.T) {
	fastRestartRetries(t)
	gateway := newPeerListener(t, "127.0.0.1:0", false)
	addr := gateway.addr()
	_ = gateway.ln.Close()
	result := run(t, "claudecode", nil, func(opts *Options) {
		opts.APIAddr = addr
		opts.HTTPClient = verifiedTestClient(addr, func(net.Conn) error { return nil })
		opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`)
		opts.FailMode = "closed"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.StartedAt = time.Now()
	})
	if nativeOutageBlocked(result) || !strings.Contains(result.stdout+result.stderr, "fail mode open for an outage") {
		t.Fatalf("a refused port is no longer an outage: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

// connectBy ends a try whose listener's owner is still being checked as
// unverified, and a try with no connection as not connected (an outage).
func TestConnectByTellsAnUnfinishedOwnerCheckFromNoConnection(t *testing.T) {
	for _, pending := range []bool{false, true} {
		tryCtx, release := connectBy(context.Background(), time.Now().Add(20*time.Millisecond))
		if check, _ := tryCtx.Value(perUserPeerCheckKey{}).(*perUserPeerCheck); check == nil {
			t.Fatal("connectBy gives the transport no owner-check mark")
		} else {
			check.pending.Store(pending)
		}
		<-tryCtx.Done()
		cause := context.Cause(tryCtx)
		err := notConnectedError(tryCtx, cause)
		release()
		if pending && (!errors.Is(err, errPerUserPeerUnverified) || gatewayRestartShaped(err) || perUserOutageError(Options{}, err)) {
			t.Errorf("an unfinished owner check is an outage: %v", err)
		}
		if !pending && (!errors.Is(err, errGatewayNotConnected) || !perUserOutageError(Options{}, err)) {
			t.Errorf("no connection is no longer an outage: %v", err)
		}
	}
	// A refusal stays final under every wrap the hook adds.
	for _, err := range []error{
		fmt.Errorf("%w: %w", errPerUserPeerUnverified, syscall.ECONNREFUSED),
		fmt.Errorf("%w: %w", errGatewayNotConnected, fmt.Errorf("%w: %w", errPerUserPeerUnverified, io.EOF)),
		errPerUserPeerCheckUnfinished,
	} {
		if gatewayRestartShaped(err) {
			t.Errorf("a refused listener is retried as a restart: %v", err)
		}
	}
}
