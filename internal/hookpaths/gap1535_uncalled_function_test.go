// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1535: a function body the command never calls never runs, so a
// protected write in it is not a protected target of the command. A call,
// an export -f to a child shell, a trap and a name the shell calls on its
// own (command_not_found_handle) keep the body checked.
func TestActionUncalledFunctionBodyIsNotATarget(t *testing.T) {
	skipPOSIXGrammarOnWindows(t)
	home := t.TempDir()
	cwd := home
	body := "f() { echo marker >> ~/.ssh/authorized_keys; }; "
	for _, tc := range []struct {
		command, want string
	}{
		{body + "echo ok", ""},
		{"g() { cp k.pub ~/.ssh/authorized_keys; }\nmake test", ""},
		{body + "f", "protected-target"},
		{body + "echo ok; f", "protected-target"},
		{body + "export -f f; bash -c f", "protected-target"},
		{body + "trap f EXIT", "protected-target"},
		{body + "xargs -n1 f < list", "protected-target"},
		{"command_not_found_handle() { echo k >> ~/.ssh/authorized_keys; }; nosuchprog", "protected-target"},
		{"f() { :; }; echo k >> ~/.ssh/authorized_keys", "protected-target"},
	} {
		if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
			t.Errorf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
}
