// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serveHookCall judges one hook call. A managed gateway cannot open the
// user's home, so it is closed for the managed calls and judges only the
// targets the hook client lists; a per-user gateway opens it.
func serveHookCall(t *testing.T, f b36ManagedHookFixture, call *hookCall) {
	t.Helper()
	if call.managed {
		if err := os.Chmod(f.homes, 0); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(f.homes, 0o700); err != nil {
				t.Error(err)
			}
		}()
	}
	call.verdict, call.body = f.serve(call)
}

// copyThroughVariableRows are the GAP-0934 rows: the shell expands
// NAME=${OTHER:-word} (and NAME=$OTHER) where the assignment sits, so a later
// rebinding of OTHER does not change NAME, and a null OTHER takes the word of
// :-.
var copyThroughVariableRows = []struct {
	command, want string
	// managedOnly: the per-user gateway reads the variable operand of a
	// command that binds a protected name anywhere as a candidate (a reader
	// older than GAP-0934, same answer on the merge base), so only the
	// managed answer, which this change decides, is pinned.
	managedOnly bool
}{
	{`p=out.txt; f=${p:-keylink}; cp a.txt "$f"`, "allow", false},
	{`p=out.txt; f=${p:-keylink}; p=other.txt; cp a.txt "$f"`, "allow", false},
	{`p=out.txt; f=${p-keylink}; p=other.txt; cp a.txt "$f"`, "allow", false},
	{`p=out.txt; f=$p; p=other.txt; cp a.txt "$f"`, "allow", false},
	{`p=out.txt; f=${p:-keylink}; p=keylink; cp a.txt "$f"`, "allow", true},
	{`p=out.txt; f=${p:-keylink}; p+=more; cp a.txt "$f"`, "allow", false},
	{`p=out.txt; f=${p:-keylink}; q=$f; p=other.txt; cp a.txt "$q"`, "allow", false},
	{`p=out.txt; f=${p:-keylink}; p=out.txt; cp a.txt "$f"`, "allow", false},
	{`p=; f=${p:-out.txt}; cp a.txt "$f"`, "allow", false},
	{`p=; f=${p-out.txt}; cp a.txt "$f"`, "allow", false},
	{`p=keylink; f=${p:-out.txt}; cp a.txt "$f"`, "block", false},
	{`p=keylink; f=${p:-out.txt}; p=other.txt; cp a.txt "$f"`, "block", false},
	{`p=keylink; f=$p; p=other.txt; cp a.txt "$f"`, "block", false},
	{`p=../.ssh/authorized_keys; f=${p:-out.txt}; p=other.txt; cp a.txt "$f"`, "block", false},
	{`p=../.ssh/authorized_keys; f=$p; p=other.txt; cp a.txt "$f"`, "block", false},
	{`p=; f=${p:-../.ssh/authorized_keys}; cp a.txt "$f"`, "block", false},
	{`p=out.txt; f=${p:-../.ssh/authorized_keys}; p=other.txt; cp a.txt "$f"`, "allow", false},
	{`p=out.txt; f=${p-../.ssh/authorized_keys}; p=other.txt; cp a.txt "$f"`, "allow", false},
}

// copyThroughVariableFixture is the B36 managed hook fixture with a link to
// the SSH folder and an ordinary source file in the project.
func copyThroughVariableFixture(t *testing.T) b36ManagedHookFixture {
	t.Helper()
	f := newB36ManagedHookFixture(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "sshlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// judgeCopyThroughVariable judges command on the given calls and wants want.
func judgeCopyThroughVariable(t *testing.T, f b36ManagedHookFixture, calls []*hookCall, want string) {
	t.Helper()
	for _, call := range calls {
		serveHookCall(t, f, call)
		if call.verdict != want {
			t.Errorf("%s: %s, want %s: %.300s", call.name, call.verdict, want, call.body)
		}
	}
}

// TestCopyThroughAVariableSetFromAnotherReadsTheBindingInEffectAtTheCopy pins
// GAP-0934: an ordinary copy through such a name stays allowed and a copy
// whose name was fixed to the protected file before the rebinding stays
// blocked. Each row is judged by one managed and one per-user gateway, on
// different connectors that swap from row to row; a managed-only row by the
// managed one.
func TestCopyThroughAVariableSetFromAnotherReadsTheBindingInEffectAtTheCopy(t *testing.T) {
	f := copyThroughVariableFixture(t)
	for index, row := range copyThroughVariableRows {
		t.Run(row.command, func(t *testing.T) {
			payload := f.payload(t, row.command)
			// everyMode: Claude Code managed, per-user, then Codex managed,
			// per-user.
			modes := everyMode(row.command, payload, f.clientHeader(t, payload))
			calls := []*hookCall{modes[0], modes[3]}
			if index%2 == 1 {
				calls = []*hookCall{modes[2], modes[1]}
			}
			if row.managedOnly {
				calls = calls[:1]
			}
			judgeCopyThroughVariable(t, f, calls, row.want)
		})
	}
}

// TestCopyThroughAVariableSetFromAnotherIsBlockedPastTheCommandBound pins the
// copy through a name fixed to the protected link before the rebinding
// blocked by the managed Claude Code hook with the command padded over the
// command bound.
func TestCopyThroughAVariableSetFromAnotherIsBlockedPastTheCommandBound(t *testing.T) {
	copyThroughVariablePadded(t, `p=keylink; f=${p:-out.txt}; p=other.txt; cp a.txt "$f"`, 0, "block")
}

// TestCopyThroughAVariableSetFromAnOrdinaryNameIsAllowedPastTheCommandBound
// pins the ordinary twin allowed by the managed Codex hook, padded the same.
func TestCopyThroughAVariableSetFromAnOrdinaryNameIsAllowedPastTheCommandBound(t *testing.T) {
	copyThroughVariablePadded(t, `p=out.txt; f=${p:-keylink}; p=other.txt; cp a.txt "$f"`, 2, "allow")
}

// copyThroughVariablePadded judges command padded over the command bound in
// the everyMode mode with the given index.
func copyThroughVariablePadded(t *testing.T, command string, mode int, want string) {
	t.Helper()
	f := copyThroughVariableFixture(t)
	padded := command + strings.Repeat(" ", 70000)
	payload := f.payload(t, padded)
	judgeCopyThroughVariable(t, f, everyMode(command, payload, f.clientHeader(t, payload))[mode:mode+1], want)
}
