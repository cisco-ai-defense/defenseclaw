// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
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

// TestCopyThroughAVariableSetFromAnotherReadsTheBindingInEffectAtTheCopy pins
// GAP-0934: the shell expands NAME=${OTHER:-word} (and NAME=$OTHER) where the
// assignment sits, so a later rebinding of OTHER does not change NAME, and a
// null OTHER takes the word of :-. An ordinary copy through such a name stays
// allowed in every profile, mode and connector, and a copy whose name was
// fixed to the protected file before the rebinding stays blocked, with the
// command as it is and padded over the command bound.
func TestCopyThroughAVariableSetFromAnotherReadsTheBindingInEffectAtTheCopy(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "sshlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		command, want string
		// managedOnly: the per-user gateway reads the variable operand of
		// a command that binds a protected name anywhere as a candidate
		// (a reader older than GAP-0934, same answer on the merge base),
		// so only the managed answer, which this change decides, is pinned.
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
	} {
		for _, pad := range []int{0, 70000} {
			command := row.command + strings.Repeat(" ", pad)
			t.Run(fmt.Sprintf("%s/pad%d", row.command, pad), func(t *testing.T) {
				payload := f.payload(t, command)
				header := f.clientHeader(t, payload)
				for _, call := range everyMode(command, payload, header) {
					if row.managedOnly && !call.managed {
						continue
					}
					serveHookCall(t, f, call)
					if call.verdict != row.want {
						t.Errorf("%s: %s, want %s: %.300s", call.name, call.verdict, row.want, call.body)
					}
				}
			})
		}
	}
}
