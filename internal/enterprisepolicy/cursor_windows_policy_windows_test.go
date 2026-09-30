//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"path/filepath"
	"strings"
	"testing"
)

// On Windows the standalone guardian publishes Cursor's enterprise
// hooks.json only while a user is enrolled for Cursor. `enterprise policy
// show` and `verify` used to say only that the file does not exist; they now
// say why it can be absent and where to look.
func TestWindowsCursorVerifyExplainsAnUnpublishedHooksFile(t *testing.T) {
	opts := windowsTestOptions(t)
	state, err := cursorTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(opts.WindowsProgramData, "Cursor", "hooks.json")
	if state.Covered || len(state.Conflicts) != 1 {
		t.Fatalf("state = %+v, want one conflict and not covered", state)
	}
	want := hooks + " does not exist: the guardian publishes it only while at least one user is enrolled for Cursor"
	if !strings.HasPrefix(state.Conflicts[0], want) || !strings.Contains(state.Conflicts[0], "enterprise windows status") {
		t.Fatalf("conflict = %q, want it to start with %q and point at enterprise windows status", state.Conflicts[0], want)
	}
}
