// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"net"
	"os"
	"strings"
	"testing"
)

// A present socket can pass the ownership check and still refuse a later
// connection. The administrator's outage open is reserved for a missing
// socket in a trusted directory, never a failed verified transport.
func TestManagedStandaloneShellHooksOpenBlocksFailedVerifiedSocket(t *testing.T) {
	for _, conn := range []Connector{
		NewAntigravityConnector(), NewClaudeCodeConnector(), NewCodexConnector(),
		NewCopilotConnector(), NewCursorConnector(), NewDevinConnector(),
		NewHermesConnector(), NewKiroConnector(),
	} {
		t.Run(conn.Name(), func(t *testing.T) {
			f := newHookSocketFixture(t, "dcsr", nil)
			if err := os.Remove(f.socket); err != nil {
				t.Fatal(err)
			}
			stale, err := net.Listen("unix", f.socket)
			if err != nil {
				t.Fatal(err)
			}
			stale.(*net.UnixListener).SetUnlinkOnClose(false)
			if err := stale.Close(); err != nil {
				t.Fatal(err)
			}
			hook := hookArgvConnectorCase(t, conn.Name())
			code, stdout, stderr := runStandaloneShellHookInMode(t, f, conn, hook.script, hook.args, hook.stdin, "open")
			blocked := code == 2 || strings.Contains(stdout, `"deny"`) ||
				strings.Contains(stdout, `"block"`) || strings.Contains(stdout, `"continue":false`)
			if !blocked || !strings.Contains(stderr, "enterprise_managed_gateway_peer_unverified") {
				t.Fatalf("verified socket refused: exit %d stdout=%q stderr=%q, want a peer-unverified block", code, stdout, stderr)
			}
			if paths, _, _ := f.gateway.recorded(); len(paths) != 0 || f.tcpConnections.Load() != 0 {
				t.Fatalf("failed socket must not send through TCP or the old socket: paths=%q tcp=%d", paths, f.tcpConnections.Load())
			}
		})
	}
}

func TestManagedStandaloneOpenRequiresTrustedDirectoryForMissingSocket(t *testing.T) {
	f := newHookSocketFixture(t, "dcsd", nil)
	if err := os.Remove(f.socket); err != nil {
		t.Fatal(err)
	}
	f.untrustSocketDir(t)
	hook := hookArgvConnectorCase(t, "kiro")
	code, stdout, stderr := runStandaloneShellHookInMode(t, f, NewKiroConnector(), hook.script, hook.args, hook.stdin, "open")
	if code != 2 || !strings.Contains(stderr, "enterprise_managed_gateway_peer_unverified") || strings.Contains(stdout, "allow") {
		t.Fatalf("missing socket in untrusted directory: exit %d stdout=%q stderr=%q, want a peer-unverified block", code, stdout, stderr)
	}
	if err := os.Chmod(f.runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runStandaloneShellHookInMode(t, f, NewKiroConnector(), hook.script, hook.args, hook.stdin, "open")
	if code != 0 || !strings.Contains(stderr, "enterprise_managed_gateway_not_running") {
		t.Fatalf("missing socket in trusted directory: exit %d stdout=%q stderr=%q, want the selected outage mode", code, stdout, stderr)
	}
	if err := os.Remove(f.runDir); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runStandaloneShellHookInMode(t, f, NewKiroConnector(), hook.script, hook.args, hook.stdin, "open")
	if code != 2 || !strings.Contains(stderr, "hook socket directory is missing") || strings.Contains(stderr, "not owned") {
		t.Fatalf("missing socket directory: exit %d stdout=%q stderr=%q, want an accurate closed failure", code, stdout, stderr)
	}
}
