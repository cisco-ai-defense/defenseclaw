// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpriority

import (
	"testing"

	"golang.org/x/sys/windows"
)

func setClass(t *testing.T, class uint32) {
	t.Helper()
	if err := windows.SetPriorityClass(windows.CurrentProcess(), class); err != nil {
		t.Fatalf("set priority class %#x: %v", class, err)
	}
}

func currentClass(t *testing.T) uint32 {
	t.Helper()
	class, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	return class
}

// GAP-0155, GAP-0167, GAP-0171: a hook process runs above normal priority,
// from below normal, idle or normal alike, so the normal-priority work of a
// Setup ensure or repair and of a starting gateway does not hold its answer
// past its deadline. Other entrypoints keep their class, and a class above
// normal is kept.
func TestAHookProcessRunsAboveNormalPriority(t *testing.T) {
	original := currentClass(t)
	t.Cleanup(func() { setClass(t, original) })
	for _, from := range []uint32{windows.NORMAL_PRIORITY_CLASS, windows.BELOW_NORMAL_PRIORITY_CLASS, windows.IDLE_PRIORITY_CLASS} {
		setClass(t, from)
		if !raiseForHook([]string{"hook", "--connector", "claudecode", "--enterprise-managed"}) {
			t.Fatalf("from %#x: the hook did not raise its class", from)
		}
		if class := currentClass(t); class != windows.ABOVE_NORMAL_PRIORITY_CLASS {
			t.Fatalf("from %#x: hook class %#x, want above normal", from, class)
		}
	}
	for _, from := range []uint32{windows.NORMAL_PRIORITY_CLASS, windows.BELOW_NORMAL_PRIORITY_CLASS} {
		setClass(t, from)
		if !raiseForHook([]string{LauncherGuardSubcommand, `C:\Users\u\.local\bin\defenseclaw-hook.exe`, "hook", "--connector", "claudecode"}) {
			t.Fatalf("from %#x: the launcher guard did not raise its class", from)
		}
		if class := currentClass(t); class != windows.ABOVE_NORMAL_PRIORITY_CLASS {
			t.Fatalf("from %#x: launcher guard class %#x, want above normal", from, class)
		}
	}
	setClass(t, windows.NORMAL_PRIORITY_CLASS)
	for _, args := range [][]string{nil, {"notify"}, {"--version"}, {"--version-json"}, {"start", "hook"}, {"start", LauncherGuardSubcommand}} {
		if raiseForHook(args) || currentClass(t) != windows.NORMAL_PRIORITY_CLASS {
			t.Fatalf("%q raised the class to %#x", args, currentClass(t))
		}
	}
	setClass(t, windows.HIGH_PRIORITY_CLASS)
	if raiseForHook([]string{"hook"}) || currentClass(t) != windows.HIGH_PRIORITY_CLASS {
		t.Fatalf("a high class was changed to %#x", currentClass(t))
	}
}
