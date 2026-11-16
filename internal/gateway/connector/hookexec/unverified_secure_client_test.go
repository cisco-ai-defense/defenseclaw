// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A managed hook whose process looks like Secure Client (neither the Unix
// standalone hook nor the Windows standalone binary) but whose host the
// strict Secure Client classifier did not verify (opts.SecureClient false)
// gets none of the Secure Client openings (#1163, main-sync review finding
// 5): it is a standalone hook, which follows the fail mode its
// administrator-owned runtime records (owner decision 2026-10-20). In fail
// mode closed a stopped gateway and an unreadable Copilot answer get the
// managed deny.
func TestUnverifiedSecureClientHostManagedHookIsStandalone(t *testing.T) {
	// Such a hook is a standalone one: its fail mode is the one its
	// administrator-owned runtime records (owner decision 2026-10-20), so a
	// stopped gateway follows it, and an unverified peer stays closed.
	opts := Options{ManagedEnterprise: true, SecureClient: false}
	for _, mode := range []string{"open", "closed"} {
		if got := managedPeerFailMode(opts, mode, errManagedGatewayNotRunning); got != mode {
			t.Fatalf("unverified host, stopped gateway, fail mode %s: = %q", mode, got)
		}
	}
	if got := managedPeerFailMode(opts, "open", errManagedGatewayPeerUnverified); got != "closed" {
		t.Fatalf("unverified host, unverified peer: fail mode = %q, want closed", got)
	}
	opts.SecureClient = true
	if got := managedPeerFailMode(opts, "open", errManagedGatewayNotRunning); got != "open" {
		t.Fatalf("authenticated Secure Client, stopped gateway: fail mode = %q, want open", got)
	}
	if got := managedPeerFailMode(opts, "open", errManagedGatewayPeerUnverified); got != "closed" {
		t.Fatalf("authenticated Secure Client, unverified peer: fail mode = %q, want closed", got)
	}

	sp := specs["copilot"]
	for _, fail := range []func(Options) int{
		func(o Options) int { return failUnreachable(o, sp, "closed", managedGatewayNotRunningReason) },
		func(o Options) int { return failResponse(o, sp, "closed", "invalid JSON response") },
	} {
		home := t.TempDir()
		var stdout, stderr bytes.Buffer
		o := Options{Connector: "copilot", Event: "preToolUse", ManagedEnterprise: true, SecureClient: false,
			Home: home, FailureLogHome: userLogHome(home), Stdout: &stdout, Stderr: &stderr, Now: time.Now}
		if code := fail(o); code != 0 || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
			t.Fatalf("unverified host Copilot: code=%d stdout=%q, want the managed deny", code, stdout.String())
		}
		failures, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
		if !strings.Contains(string(failures), `"outcome":"fail_closed"`) {
			t.Fatalf("unverified host Copilot logged %q, want fail_closed", failures)
		}
	}
}
