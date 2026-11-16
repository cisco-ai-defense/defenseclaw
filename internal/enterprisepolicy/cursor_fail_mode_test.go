// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"strings"
	"testing"
)

// Owner decision 2026-10-20: the Unix machine-policy Cursor hooks carry the
// administrator's fail mode: failClosed true by default, false when the
// config resolves Cursor open (CursorFailOpen), and verify holds the file to
// that value.
func TestCursorMachinePolicyFollowsTheFailMode(t *testing.T) {
	opts := testOptions(t)
	opts.CursorFailOpen = true
	path, _ := CursorEnterpriseHooksPath(opts)
	if _, err := (cursorTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	if body := readFile(t, path); !strings.Contains(body, `"failClosed": false`) || strings.Contains(body, `"failClosed": true`) {
		t.Fatalf("open Cursor machine policy is not failClosed false:\n%s", body)
	}
	state, err := cursorTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	opts.CursorFailOpen = false
	state, err = cursorTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConflict(state, "not failClosed") {
		t.Fatalf("verify accepted an open entry for a closed fail mode: %+v", state.Conflicts)
	}
	if _, err := (cursorTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	if body := readFile(t, path); !strings.Contains(body, `"failClosed": true`) {
		t.Fatalf("reconcile did not restore failClosed true:\n%s", body)
	}
}
