//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// activationSocket is a hook socket systemd holds for a masked gateway
// service: it takes the connection into its backlog and never answers;
// after a moment the failed activation closes the socket unit, which resets
// the queued connection and, when gone is set, removes the socket file.
func activationSocket(t *testing.T, path string, gone bool) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	unix := listener.(*net.UnixListener)
	unix.SetUnlinkOnClose(gone)
	go func() {
		time.Sleep(100 * time.Millisecond)
		// Without gone the socket file stays: nothing proves the service
		// stopped.
		_ = listener.Close()
	}()
	t.Cleanup(func() { _ = listener.Close() })
}

func activationFailureRun(t *testing.T, socket, failMode string) runResult {
	t.Helper()
	previous := standaloneGatewayServiceProbe
	standaloneGatewayServiceProbe = func(context.Context) (gatewayServiceState, error) {
		return gatewayServiceState{Active: "inactive", Sub: "dead"}, nil
	}
	t.Cleanup(func() { standaloneGatewayServiceProbe = previous })
	home := t.TempDir()
	var out, errb bytes.Buffer
	code := Run(t.Context(), Options{
		Connector:         "claudecode",
		Event:             "PreToolUse",
		APIAddr:           "127.0.0.1:18970",
		FailMode:          failMode,
		Home:              home,
		HookDir:           filepath.Join(home, "hooks"),
		Stdin:             strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`),
		Stdout:            &out,
		Stderr:            &errb,
		ManagedEnterprise: true,
		ManagedStandalone: true,
		ManagedUnixSocket: socket,
		ManagedServiceUID: os.Getuid(),
		StartedAt:         time.Now(),
	})
	return runResult{stdout: out.String(), stderr: errb.String(), code: code}
}

// GAP-0807: with the gateway service masked and its hook socket active, the
// first call of an outage reaches the socket systemd holds; the activation
// fails, the queued connection is reset and the socket unit removes the
// socket. That call must be classified like every later call of the outage
// (the socket proven missing in its trusted folder: the service is not
// running), so it follows the administrator's mode instead of failing
// closed as "gateway unreachable".
func TestManagedFirstOutageCallOnAFailedActivationSocketFollowsTheAdminMode(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		wantAllow bool
	}{{"open", true}, {"closed", false}} {
		t.Run(tc.mode, func(t *testing.T) {
			socket := filepath.Join(shortSocketDir(t), "hook.sock")
			activationSocket(t, socket, true)
			result := activationFailureRun(t, socket, tc.mode)
			out := result.stdout + result.stderr
			denied := strings.Contains(result.stdout, `"permissionDecision":"deny"`)
			if result.code != 0 || denied == tc.wantAllow || !strings.Contains(out, managedGatewayNotRunningReason) {
				t.Fatalf("mode %s: exit %d stdout=%q stderr=%q, want allow=%t with %s",
					tc.mode, result.code, result.stdout, result.stderr, tc.wantAllow, managedGatewayNotRunningReason)
			}
		})
	}
}

// A socket file that stays after the connection was dropped proves
// nothing: an open mode still fails closed.
func TestManagedDroppedCallOnASocketThatStaysFailsClosedInOpenMode(t *testing.T) {
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	activationSocket(t, socket, false)
	result := activationFailureRun(t, socket, "open")
	if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
		strings.Contains(result.stdout+result.stderr, managedGatewayNotRunningReason) {
		t.Fatalf("stale socket: exit %d stdout=%q stderr=%q, want a closed deny", result.code, result.stdout, result.stderr)
	}
}
