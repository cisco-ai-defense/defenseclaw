// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-1150: in this account's install window a per-user hook whose gateway
// has no listener answered only after Windows gave up its SYN retries to the
// stopped gateway's loopback port and the restart budget ran out (2-4 s).
// With the lock held and no LISTEN row the hook answers the install-window
// deny at once, without a dial; with a listener (the new gateway is up, the
// lock not yet released) or an unreadable table it dials and keeps the
// gateway's answer.
func TestPerUserInstallWindowSkipsTheDialWithoutAListener(t *testing.T) {
	for _, tc := range []struct {
		name              string
		listening, known  bool
		wantRequests      int
		wantInstallAnswer bool
	}{
		{"lock held, no listener", false, true, 0, true},
		{"lock held, listener up", true, true, 1, false},
		{"lock held, table unreadable", false, false, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := perUserInstallWindowListening
			t.Cleanup(func() { perUserInstallWindowListening = previous })
			var looked []string
			perUserInstallWindowListening = func(address string) (bool, bool) {
				looked = append(looked, address)
				return tc.listening, tc.known
			}
			started := time.Now()
			result := run(t, "claudecode", ok(`{"action":"allow"}`), func(opts *Options) {
				opts.StartedAt = started
				opts.perUserLoopbackDial = true
				// install.ps1's lock: the recovery of a per-user hook starts
				// no gateway during an install (perUserGatewayRecovery).
				opts.GatewayRecovery = func(context.Context, error) error { return nil }
				if err := os.Mkdir(filepath.Join(opts.Home, installLockName), 0o700); err != nil {
					t.Fatal(err)
				}
			})
			elapsed := time.Since(started)
			if result.rt.requests != tc.wantRequests {
				t.Fatalf("requests = %d, want %d (looked up %v)", result.rt.requests, tc.wantRequests, looked)
			}
			if len(looked) == 0 || looked[0] != "127.0.0.1:8787" {
				t.Fatalf("listener lookups = %v, want the dialled IPv4 endpoint", looked)
			}
			installAnswer := strings.Contains(result.stdout, "being installed or upgraded")
			if installAnswer != tc.wantInstallAnswer {
				t.Fatalf("install-window answer = %v, want %v: code=%d stdout=%q stderr=%q",
					installAnswer, tc.wantInstallAnswer, result.code, result.stdout, result.stderr)
			}
			if tc.wantInstallAnswer {
				if !claudeBlocked(result) {
					t.Fatalf("no-listener call in the install window was not denied: stdout=%q", result.stdout)
				}
				if elapsed > 500*time.Millisecond {
					t.Fatalf("install-window answer took %v, want it at once (no SYN wait, no restart wait)", elapsed)
				}
			} else if claudeBlocked(result) {
				t.Fatalf("the gateway's allow was not kept: stdout=%q", result.stdout)
			}
		})
	}
}

// Outside the install window, for a managed hook and for a client the hook
// did not make, the listener table is not read: a cold start relies on the
// dialled refusal.
func TestPerUserListenerTableIsReadOnlyInTheInstallWindow(t *testing.T) {
	previous := perUserInstallWindowListening
	t.Cleanup(func() { perUserInstallWindowListening = previous })
	lookups := 0
	perUserInstallWindowListening = func(string) (bool, bool) { lookups++; return false, true }
	home := t.TempDir()
	opts := Options{APIAddr: "127.0.0.1:8787", Home: home, perUserLoopbackDial: true}
	if perUserInstallWindowWithoutListener(opts) || lookups != 0 {
		t.Fatalf("no lock: lookups=%d", lookups)
	}
	if err := os.Mkdir(filepath.Join(home, installLockName), 0o700); err != nil {
		t.Fatal(err)
	}
	injected := opts
	injected.perUserLoopbackDial = false
	managed := opts
	managed.ManagedEnterprise = true
	if perUserInstallWindowWithoutListener(injected) || perUserInstallWindowWithoutListener(managed) || lookups != 0 {
		t.Fatalf("injected client or managed hook read the table: lookups=%d", lookups)
	}
	if !perUserInstallWindowWithoutListener(opts) || lookups != 1 {
		t.Fatalf("install window without a listener: lookups=%d", lookups)
	}
}
