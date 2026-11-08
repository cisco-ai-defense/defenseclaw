// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0916: a Claude Code or Codex hook call from a running agent after the
// administrator removed the connector from the roster (its machine policy is
// gone) is allowed with no gateway contact, as the Cursor tombstone allows it.
// While the connector is on the roster, an account that is not enrolled for it
// keeps the "not enrolled yet" refusal, and Secure Client keeps its behaviour.
func TestEnterpriseManagedRuntimeAbsenceNoopAllowsARemovedStandaloneConnector(t *testing.T) {
	previous := standaloneEnterpriseHookCheck
	t.Cleanup(func() { standaloneEnterpriseHookCheck = previous })
	exe := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	for _, tc := range []struct {
		name       string
		connector  string
		standalone bool
		active     bool
		registered bool
		resolveErr error
		want       bool
	}{
		{name: "claudecode removed", connector: "claudecode", standalone: true, want: true},
		{name: "codex removed", connector: "codex", standalone: true, want: true},
		{name: "claudecode on the roster, account unregistered", connector: "claudecode", standalone: true, active: true},
		{name: "codex on the roster, account unregistered", connector: "codex", standalone: true, active: true},
		{name: "registered account", connector: "codex", standalone: true, active: true, registered: true},
		{name: "unreadable runtime state", connector: "claudecode", standalone: true, resolveErr: errors.New("tampered")},
		{name: "secure client", connector: "claudecode", standalone: false},
		{name: "a per-user connector", connector: "copilot", standalone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			standaloneEnterpriseHookCheck = func(string) bool { return tc.standalone }
			nativeEnterpriseHookRuntimeSnapshot.Lock()
			nativeEnterpriseHookRuntimeSnapshot.prepared = true
			nativeEnterpriseHookRuntimeSnapshot.executable = exe
			nativeEnterpriseHookRuntimeSnapshot.connector = tc.connector
			nativeEnterpriseHookRuntimeSnapshot.err = nil
			nativeEnterpriseHookRuntimeSnapshot.Unlock()
			t.Cleanup(func() {
				nativeEnterpriseHookRuntimeSnapshot.Lock()
				nativeEnterpriseHookRuntimeSnapshot.prepared = false
				nativeEnterpriseHookRuntimeSnapshot.err = nil
				nativeEnterpriseHookRuntimeSnapshot.Unlock()
			})
			got := enterpriseManagedRuntimeAbsenceNoop(exe, tc.connector, tc.active, tc.registered, tc.resolveErr)
			if got != tc.want {
				t.Fatalf("no-op = %t, want %t", got, tc.want)
			}
			nativeEnterpriseHookRuntimeSnapshot.Lock()
			err := nativeEnterpriseHookRuntimeSnapshot.err
			nativeEnterpriseHookRuntimeSnapshot.Unlock()
			unregistered := errors.Is(err, enterprisehooks.ErrWindowsManagedSIDUnregistered)
			// The refusal is set exactly where the call is not allowed and the
			// connector's policy is absent without an unreadable state.
			wantRefusal := !tc.want && !tc.active && !tc.registered && tc.resolveErr == nil
			if unregistered != wantRefusal {
				t.Fatalf("unregistered refusal set = %t, want %t (err %v)", unregistered, wantRefusal, err)
			}
		})
	}
}
