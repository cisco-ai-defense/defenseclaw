// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0979: the machine-wide hook of a standalone computer lets the calls of an
// account the administrator excludes from enrollment pass, instead of refusing
// them with the text of a pending enrollment. It does so only when the
// resolver failed for the account being absent from the protected target set,
// the hook is the standalone one, the hot-config undo closure is neither held
// nor unreadable, and the guardian has published a valid marker for the
// calling SID. An account that is not excluded keeps the refusal that tells it
// to wait for its enrollment.
func TestEnterpriseManagedRuntimeAbsenceNoopLetsAnExcludedAccountPass(t *testing.T) {
	previousCheck, previousClosure, previousExcluded := standaloneEnterpriseHookCheck, windowsStandaloneHooksHeldClosed, windowsCurrentAccountExcluded
	t.Cleanup(func() {
		standaloneEnterpriseHookCheck, windowsStandaloneHooksHeldClosed, windowsCurrentAccountExcluded = previousCheck, previousClosure, previousExcluded
	})
	exe := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	unregistered := fmt.Errorf("%w: connector claudecode current SID is absent from the protected target set", enterprisehooks.ErrWindowsManagedSIDUnregistered)
	type row struct {
		name        string
		connector   string
		standalone  bool
		registered  bool
		resolveErr  error
		closureHeld bool
		closureErr  error
		excluded    bool
		markerErr   error
		want        bool
	}
	for _, tc := range []row{
		{name: "excluded account, claudecode", connector: "claudecode", standalone: true, resolveErr: unregistered, excluded: true, want: true},
		{name: "excluded account, codex", connector: "codex", standalone: true, resolveErr: unregistered, excluded: true, want: true},
		{name: "excluded account, cursor", connector: "cursor", standalone: true, resolveErr: unregistered, excluded: true, want: true},
		{name: "account not excluded (enrollment pending) keeps the refusal", connector: "claudecode", standalone: true, resolveErr: unregistered},
		{name: "marker damaged or directory untrusted keeps the refusal", connector: "claudecode", standalone: true, resolveErr: unregistered, markerErr: errors.New("changed")},
		{name: "closure held (failed undo)", connector: "claudecode", standalone: true, resolveErr: unregistered, excluded: true, closureHeld: true},
		{name: "closure unreadable", connector: "claudecode", standalone: true, resolveErr: unregistered, excluded: true, closureHeld: true, closureErr: errors.New("access is denied")},
		{name: "secure client keeps its behaviour", connector: "claudecode", standalone: false, resolveErr: unregistered, excluded: true},
		{name: "unreadable runtime state is not an exclusion", connector: "claudecode", standalone: true, resolveErr: errors.New("tampered"), excluded: true},
		{name: "a registered account with no runtime yet is not an exclusion", connector: "claudecode", standalone: true, resolveErr: enterprisehooks.ErrWindowsManagedRuntimeGenerationPending, excluded: true},
		{name: "registered account", connector: "claudecode", standalone: true, registered: true, excluded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			standaloneEnterpriseHookCheck = func(string) bool { return tc.standalone }
			windowsStandaloneHooksHeldClosed = func() (bool, error) { return tc.closureHeld, tc.closureErr }
			windowsCurrentAccountExcluded = func() (bool, error) { return tc.excluded && tc.markerErr == nil, tc.markerErr }
			nativeEnterpriseHookRuntimeSnapshot.Lock()
			nativeEnterpriseHookRuntimeSnapshot.prepared = true
			nativeEnterpriseHookRuntimeSnapshot.executable = exe
			nativeEnterpriseHookRuntimeSnapshot.connector = tc.connector
			nativeEnterpriseHookRuntimeSnapshot.err = tc.resolveErr
			nativeEnterpriseHookRuntimeSnapshot.Unlock()
			t.Cleanup(func() {
				nativeEnterpriseHookRuntimeSnapshot.Lock()
				nativeEnterpriseHookRuntimeSnapshot.prepared = false
				nativeEnterpriseHookRuntimeSnapshot.err = nil
				nativeEnterpriseHookRuntimeSnapshot.Unlock()
			})
			if got := enterpriseManagedRuntimeAbsenceNoop(exe, tc.connector, true, tc.registered, tc.resolveErr); got != tc.want {
				t.Fatalf("enterpriseManagedRuntimeAbsenceNoop = %t, want %t", got, tc.want)
			}
		})
	}
}
