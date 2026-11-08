// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shortConnectedWait(t *testing.T, wait time.Duration) {
	t.Helper()
	previous := perUserConnectedWait
	perUserConnectedWait = wait
	t.Cleanup(func() { perUserConnectedWait = previous })
}

// procTables writes fake tcp and tcp6 tables with the given rows.
func procTables(t *testing.T, tcp, tcp6 []string) string {
	t.Helper()
	dir := t.TempDir()
	header := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	for name, rows := range map[string][]string{"tcp": tcp, "tcp6": tcp6} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(header+strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestListenersAreOwnedByTheCallingAccountOnly(t *testing.T) {
	self := os.Geteuid()
	other := self + 1
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	const loop = "0100007F:4A1A"
	const anyV4 = "00000000:4A1A"
	const anyV6 = "00000000000000000000000000000000:4A1A"
	const mapped = "0000000000000000FFFF00000100007F:4A1A"
	listen := func(key string, uid int) string {
		return fmt.Sprintf("0: %s 00000000:0000 0A 0 0 0 %d 0 100", key, uid)
	}
	for _, tc := range []struct {
		name string
		tcp  []string
		tcp6 []string
		want bool
	}{
		{"own loopback listener", []string{listen(loop, self)}, nil, true},
		{"own wildcard listener", []string{listen(anyV4, self)}, nil, true},
		{"own dual-stack listener", nil, []string{listen(anyV6, self)}, true},
		{"own mapped listener", nil, []string{listen(mapped, self)}, true},
		{"foreign loopback listener", []string{listen(loop, other)}, nil, false},
		{"foreign wildcard listener", []string{listen(anyV4, other)}, nil, false},
		{"foreign dual-stack listener", nil, []string{listen(anyV6, other)}, false},
		{"own loopback with a foreign wildcard", []string{listen(loop, self), listen(anyV4, other)}, nil, false},
		{"no listener", nil, nil, false},
		{"listener on another port", []string{"0: 0100007F:1234 00000000:0000 0A 0 0 0 " + fmt.Sprint(self) + " 0 100"}, nil, false},
		{"an established row is not a listener", []string{"0: 0100007F:4A1A 0100007F:CB20 01 0 0 0 " + fmt.Sprint(self) + " 0 100"}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := listenersAreOwnedBy(procTables(t, tc.tcp, tc.tcp6), self, server); got != tc.want {
				t.Fatalf("listenersAreOwnedBy = %v, want %v", got, tc.want)
			}
		})
	}
}

// A connection nobody accepts is told apart by who listens: this account own
// listener is its gateway, stopped or frozen; a listener of another account,
// or none, stays an unverified peer.
func TestUnacceptedConnectionIsUnansweredOnlyForAnOwnListener(t *testing.T) {
	self := os.Geteuid()
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0x4A1A}
	queued := "1: 0100007F:4A1A 0100007F:CB20 01 0 0 0 0 0 0"
	for _, tc := range []struct {
		name      string
		listener  string
		unanswred bool
	}{
		{"own listener", fmt.Sprintf("0: 0100007F:4A1A 00000000:0000 0A 0 0 0 %d 0 100", self), true},
		{"foreign listener", fmt.Sprintf("0: 0100007F:4A1A 00000000:0000 0A 0 0 0 %d 0 100", self+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := procTables(t, []string{tc.listener, queued}, nil)
			err := verifyPerUserConnectedTupleIn(dir, self, 80*time.Millisecond, client, server)
			if err == nil {
				t.Fatal("an unaccepted connection was verified")
			}
			if got := errors.Is(err, errPerUserListenerUnanswered); got != tc.unanswred {
				t.Fatalf("unanswered = %v, want %v: %v", got, tc.unanswred, err)
			}
		})
	}
	t.Run("accepted by another account", func(t *testing.T) {
		accepted := fmt.Sprintf("1: 0100007F:4A1A 0100007F:CB20 01 0 0 0 %d 0 101", self+1)
		own := fmt.Sprintf("0: 0100007F:4A1A 00000000:0000 0A 0 0 0 %d 0 100", self)
		err := verifyPerUserConnectedTupleIn(procTables(t, []string{own, accepted}, nil), self, 80*time.Millisecond, client, server)
		if err == nil || errors.Is(err, errPerUserListenerUnanswered) {
			t.Fatalf("a socket accepted by another account was not refused as foreign: %v", err)
		}
	})
}

// frozenGateway is a listener of this account that accepts nothing: what a
// SIGSTOPped gateway looks like to the kernel.
func frozenGateway(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

func TestFrozenOwnGatewayTransportErrorIsNeitherForeignNorAnOutage(t *testing.T) {
	shortConnectedWait(t, 150*time.Millisecond)
	addr := frozenGateway(t)
	_, err := PostPerUserHook(context.Background(), addr, "/api/v1/claude-code/hook", nil, []byte("{}"))
	if err == nil {
		t.Fatal("a frozen gateway answered")
	}
	if !PerUserPostListenerUnanswered(err) {
		t.Fatalf("not classified as an unanswered own listener: %v", err)
	}
	if PerUserPostPeerUnverified(err) || PerUserPostOutage(err) || PerUserPostNoAnswer(err) || gatewayRestartShaped(err) {
		t.Fatalf("an unanswered own listener was classified as foreign or an outage: %v", err)
	}
}

// A frozen gateway of this account is an outage, not a listener of another
// account: the default tiers let an ordinary call and a post-tool event run
// with the outage warning, the strict tier blocks them with the outage text,
// and a tool call that names a protected file stays blocked in every tier.
func TestFrozenOwnGatewayFollowsTheOutageMode(t *testing.T) {
	shortConnectedWait(t, 150*time.Millisecond)
	project := lateOrdinaryProject(t)
	addr := frozenGateway(t)
	for _, tc := range []struct {
		name    string
		event   string
		payload string
		mode    string
		blocks  bool
	}{
		{"ordinary call, open tier", "PreToolUse", lateOrdinaryPayload(t, project, "echo hi"), "open", false},
		{"ordinary call, strict tier", "PreToolUse", lateOrdinaryPayload(t, project, "echo hi"), "closed", true},
		{"link to keys, open tier", "PreToolUse", lateOrdinaryPayload(t, project, "cat keylink"), "open", true},
		{"direct keys path, open tier", "PreToolUse", lateOrdinaryPayload(t, project, "cat ../.ssh/authorized_keys"), "open", true},
		{"post-tool event, open tier", "PostToolBatch", `{"hook_event_name":"PostToolBatch"}`, "open", false},
		{"post-tool event, strict tier", "PostToolBatch", `{"hook_event_name":"PostToolBatch"}`, "closed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
			if err != nil {
				t.Fatal(err)
			}
			result := run(t, "claudecode", nil, func(opts *Options) {
				opts.APIAddr = addr
				opts.HTTPClient = client
				opts.Event = tc.event
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return tc.mode }
				opts.Stdin = strings.NewReader(tc.payload)
			})
			output := result.stdout + result.stderr
			if strings.Contains(output, "another account") {
				t.Fatalf("a frozen gateway of this account was blamed on another account: %q", output)
			}
			if got := nativeOutageBlocked(result); got != tc.blocks {
				t.Fatalf("blocks=%v, want %v: code=%d stdout=%.400q stderr=%.400q", got, tc.blocks, result.code, result.stdout, result.stderr)
			}
			if tc.blocks && !strings.Contains(output, "did not answer") {
				t.Fatalf("the block does not say the gateway did not answer: %q", output)
			}
		})
	}
}

// The benign twin: a gateway that accepts and answers is untouched.
func TestAnsweringGatewayStillAllowsTheCall(t *testing.T) {
	shortConnectedWait(t, 150*time.Millisecond)
	addr := gatewayAt(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow"}`))
	})
	reply, err := PostPerUserHook(context.Background(), addr, "/api/v1/claude-code/hook", nil, []byte("{}"))
	if err != nil || reply.Status != http.StatusOK {
		t.Fatalf("an answering gateway was refused: status=%d err=%v", reply.Status, err)
	}
}
