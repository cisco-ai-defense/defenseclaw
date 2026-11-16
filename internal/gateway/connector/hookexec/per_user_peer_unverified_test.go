// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// peerCheckFailures are the ways proving the owner of an accepted per-user
// connection can fail. Several look like a missing endpoint or a dropped
// connection on their own: a socket table or lsof that cannot be read is
// ENOENT.
var peerCheckFailures = []struct {
	name string
	err  error
}{
	{"socket table missing", fmt.Errorf("inspect connected gateway sockets: %w", &fs.PathError{Op: "open", Path: "/proc/net/tcp", Err: syscall.ENOENT})},
	{"lsof missing", fmt.Errorf("inspect connected gateway socket: %w", &exec.Error{Name: "/usr/sbin/lsof", Err: &fs.PathError{Op: "stat", Path: "/usr/sbin/lsof", Err: syscall.ENOENT}})},
	{"not exist", fs.ErrNotExist},
	{"table read cut short", io.ErrUnexpectedEOF},
	{"table read EOF", io.EOF},
	{"reset", syscall.ECONNRESET},
	{"refused", syscall.ECONNREFUSED},
	{"another account", errors.New("connected gateway socket belongs to another account")},
}

// A listener accepted the connection, so a failed owner check is never a
// gateway outage, whatever error it carries: no classifier opens it, the
// listener receives no byte, and hook-post does not exit with the outage
// status.
func TestPerUserPeerVerificationFailureIsNeverAnOutage(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	address := server.Listener.Addr().String()
	for _, tc := range peerCheckFailures {
		t.Run(tc.name, func(t *testing.T) {
			client := verifiedPerUserHTTPClient(time.Second, address, (&net.Dialer{}).DialContext,
				func(net.Conn) error { return tc.err })
			_, err := postPluginHook(context.Background(), client, address, "/api/v1/opencode/hook", nil, []byte("{}"))
			if err == nil {
				t.Fatal("an unverified listener answered the post")
			}
			if PerUserPostOutage(err) || gatewayRestartShaped(err) || perUserOutageError(Options{}, err) {
				t.Fatalf("an unverified listener was classified as an outage: %v", err)
			}
			// connectBy's deadline on the same try is not an outage either.
			if late := fmt.Errorf("%w: %w", errGatewayNotConnected, err); gatewayRestartShaped(late) || PerUserPostOutage(late) {
				t.Fatalf("an unverified listener past the connect deadline was classified as an outage: %v", late)
			}
			if received.Load() != 0 {
				t.Fatalf("the unverified listener received %d requests", received.Load())
			}
		})
	}
}

// The native per-user hook in the outage-open tier blocks a call whose
// accepted connection fails its owner check, also when the check outlasts
// the restart budget's connect deadline. A check still running at that
// deadline is unfinished, so the call is blocked as unverified even when the
// check would pass later (rc.11 a12647ceef errPerUserPeerCheckUnfinished,
// kept by the carry over the fix/r104-oss-outage-open accepted-call mark);
// never by the outage mode.
func TestPerUserNativeHookBlocksAnUnverifiedListenerInTheOpenTier(t *testing.T) {
	fastRestartRetries(t)
	shortAnswerBudget(t, 10*time.Second)
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"allow","raw_action":"allow"}`)
	}))
	defer server.Close()
	address := server.Listener.Addr().String()
	type check struct {
		name  string
		delay time.Duration
		err   error
	}
	checks := []check{{name: "slow check fails", delay: 1300 * time.Millisecond, err: peerCheckFailures[0].err}}
	for _, failure := range peerCheckFailures {
		checks = append(checks, check{name: failure.name, err: failure.err})
	}
	checks = append(checks, check{name: "slow check passes", delay: 1300 * time.Millisecond})
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			before := received.Load()
			result := run(t, "codex", &stubRT{}, func(opts *Options) {
				opts.APIAddr = address
				opts.FailMode = "closed"
				opts.OutageFailModeNow = func() string { return "open" }
				opts.Event = "PreToolUse"
				opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`)
				// The connect deadline of the first try is 1 s away.
				opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 500*time.Millisecond)
				opts.HTTPClient = verifiedPerUserHTTPClient(0, address, (&net.Dialer{}).DialContext, func(net.Conn) error {
					time.Sleep(tc.delay)
					return tc.err
				})
			})
			output := result.stdout + result.stderr
			if strings.Contains(output, "fail mode open for an outage") {
				t.Fatalf("the outage mode answered a call a listener accepted: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
			}
			if !nativeOutageBlocked(result) {
				t.Fatalf("an unverified listener let the call run: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
			}
			if received.Load() != before {
				t.Fatalf("the unverified listener received the call")
			}
		})
	}
}
