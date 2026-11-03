// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package hookexec

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0512: a managed hook can spend part of its process budget checking its
// runtime and foreign hooks before it contacts a healthy gateway. The answer
// below arrives after the old remaining window but before the process cap.
// Run uses the same armed watchdog and verified Unix transport as the native
// managed hook command.
func TestManagedClaudeHookUsesLateHealthyGatewayAnswer(t *testing.T) {
	previousProbe := standaloneGatewayServiceProbe
	standaloneGatewayServiceProbe = func(context.Context) (gatewayServiceState, error) {
		return gatewayServiceState{Active: "active", Sub: "running"}, nil
	}
	t.Cleanup(func() { standaloneGatewayServiceProbe = previousProbe })
	dir := shortSocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	answered := make(chan struct{}, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(1300 * time.Millisecond)
		_, _ = io.WriteString(w, `{"action":"allow"}`)
		answered <- struct{}{}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	result := run(t, "claudecode", nil, func(opts *Options) {
		started := time.Now().Add(-2100 * time.Millisecond)
		opts.ManagedEnterprise = true
		opts.ManagedStandalone = true
		opts.ManagedUnixSocket = socket
		opts.ManagedServiceUID = os.Getuid()
		opts.APIAddr = "127.0.0.1:1" // the verified transport dials the Unix socket
		opts.ExplainUnenrolledAccount = true
		opts.FailMode = "closed"
		opts.HTTPClient = nil
		opts.Stdin = strings.NewReader(preToolUsePayload)
		opts.StartedAt = started
		opts.FailureLogHome = userLogHome(opts.Home)
		opts.AnswerWatchdog = ArmAnswerWatchdog(Options{
			Connector: "claudecode", Event: "PreToolUse", ManagedEnterprise: true,
			StartedAt: started, Stdout: opts.Stdout, Stderr: opts.Stderr,
			Exit: func(int) {},
		}, []byte(preToolUsePayload))
	})
	if claudeBlocked(result) || strings.Contains(result.stdout+result.stderr, managedGatewayNoAnswerReason) {
		t.Fatalf("managed hook lost a healthy allow: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	select {
	case <-answered:
	default:
		t.Fatalf("hook returned before the gateway answered: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

// A missing socket is a proven service outage. The administrator's open
// mode may let it through; the ordinary managed mode and strict availability
// still block it. No answer from a connected gateway is covered separately.
func TestManagedClaudeMissingGatewayKeepsOutageModes(t *testing.T) {
	fastRestartRetries(t)
	socket := filepath.Join(shortSocketDir(t), "missing.sock")
	for _, tc := range []struct {
		name   string
		mode   string
		strict bool
		deny   bool
	}{
		{"managed closed", "closed", false, true},
		{"administrator open", "open", false, false},
		{"strict availability", "open", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "claudecode", nil, func(opts *Options) {
				opts.ManagedEnterprise = true
				opts.ManagedStandalone = true
				opts.ManagedUnixSocket = socket
				opts.ManagedServiceUID = os.Getuid()
				opts.APIAddr = "127.0.0.1:1"
				opts.ExplainUnenrolledAccount = true
				opts.HTTPClient = nil
				opts.FailMode = tc.mode
				opts.StrictAvailability = tc.strict
				opts.Stdin = strings.NewReader(preToolUsePayload)
				opts.StartedAt = time.Now().Add(-2500 * time.Millisecond)
			})
			if got := claudeBlocked(result); got != tc.deny {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, tc.deny, result.code, result.stdout, result.stderr)
			}
		})
	}
}
