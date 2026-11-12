// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0916: a Claude Code or Codex hook call from a running agent is allowed
// with no gateway contact only when the administrator took the connector off
// the roster: its machine policy is gone, the guardian has published it as off
// the roster, and the hot-config undo closure is neither held nor unreadable.
// A failed undo (closure), a lifecycle window or any connector still on the
// roster keeps the refusal, and Secure Client keeps its behaviour.
func TestEnterpriseManagedRuntimeAbsenceNoopAllowsOnlyAConnectorRemovedFromTheRoster(t *testing.T) {
	previousCheck, previousClosure, previousRead := standaloneEnterpriseHookCheck, windowsStandaloneHooksHeldClosed, windowsConnectorOffRosterRead
	t.Cleanup(func() {
		standaloneEnterpriseHookCheck, windowsStandaloneHooksHeldClosed, windowsConnectorOffRosterRead = previousCheck, previousClosure, previousRead
	})
	exe := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	type row struct {
		name         string
		connector    string
		standalone   bool
		active       bool
		registered   bool
		resolveErr   error
		closureHeld  bool
		closureErr   error
		offRoster    bool
		offRosterErr error
		want         bool
	}
	for _, tc := range []row{
		{name: "claudecode removed and clean", connector: "claudecode", standalone: true, offRoster: true, want: true},
		{name: "codex removed and clean", connector: "codex", standalone: true, offRoster: true, want: true},
		{name: "closure held (failed undo), claudecode", connector: "claudecode", standalone: true, offRoster: true, closureHeld: true},
		{name: "closure held (failed undo), codex", connector: "codex", standalone: true, offRoster: true, closureHeld: true},
		{name: "closure unreadable", connector: "claudecode", standalone: true, offRoster: true, closureHeld: true, closureErr: errors.New("access is denied")},
		{name: "lifecycle window: policy absent, connector on the roster (no marker)", connector: "claudecode", standalone: true},
		{name: "lifecycle window, codex", connector: "codex", standalone: true},
		{name: "marker unreadable or damaged", connector: "codex", standalone: true, offRosterErr: errors.New("changed")},
		{name: "policy active, account unregistered", connector: "claudecode", standalone: true, active: true, offRoster: true},
		{name: "registered account", connector: "codex", standalone: true, active: true, registered: true, offRoster: true},
		{name: "unreadable runtime state", connector: "claudecode", standalone: true, offRoster: true, resolveErr: errors.New("tampered")},
		{name: "secure client", connector: "claudecode", standalone: false, offRoster: true},
		{name: "a per-user connector", connector: "copilot", standalone: true, offRoster: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			standaloneEnterpriseHookCheck = func(string) bool { return tc.standalone }
			windowsStandaloneHooksHeldClosed = func() (bool, error) { return tc.closureHeld, tc.closureErr }
			windowsConnectorOffRosterRead = func(string) (bool, error) { return tc.offRoster, tc.offRosterErr }
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
