// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

const sidecarPriorityHelperEnv = "DEFENSECLAW_TEST_SIDECAR_HOOK_PRIORITY"

// GAP-0050: a Windows gateway answers at the hooks' above-normal class, from
// a normal start and from the below-normal class a lifecycle run or a
// scheduled task passes on; a higher class is kept, and a program the
// gateway starts runs at normal priority. The check runs in a child process
// so the test binary keeps its own class.
func TestSidecarAnswersAtTheHookPriorityClass(t *testing.T) {
	if os.Getenv(sidecarPriorityHelperEnv) == "1" {
		self := windows.CurrentProcess()
		for _, start := range []uint32{windows.NORMAL_PRIORITY_CLASS, windows.BELOW_NORMAL_PRIORITY_CLASS, windows.IDLE_PRIORITY_CLASS} {
			if err := windows.SetPriorityClass(self, start); err != nil {
				t.Fatal(err)
			}
			sidecarAnswerAtHookPriority()
			if class, err := windows.GetPriorityClass(self); err != nil || class != windows.ABOVE_NORMAL_PRIORITY_CLASS {
				t.Fatalf("gateway started at %#x runs at %#x (%v), want above normal", start, class, err)
			}
		}
		sidecarAnswerAtHookPriority() // a second call keeps the class
		child := exec.Command(os.Args[0], "-test.run=^TestSidecarChildPriorityHelper$")
		child.Env = append(os.Environ(), sidecarPriorityHelperEnv+"=child")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("a program the gateway starts: %v\n%s", err, output)
		}
		if err := windows.SetPriorityClass(self, windows.HIGH_PRIORITY_CLASS); err == nil {
			sidecarAnswerAtHookPriority()
			if class, _ := windows.GetPriorityClass(self); class != windows.HIGH_PRIORITY_CLASS {
				t.Fatalf("a high-priority gateway was changed to %#x", class)
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSidecarAnswersAtTheHookPriorityClass$", "-test.v")
	cmd.Env = append(os.Environ(), sidecarPriorityHelperEnv+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v\n%s", err, output)
	}
}

func TestSidecarChildPriorityHelper(t *testing.T) {
	if os.Getenv(sidecarPriorityHelperEnv) != "child" {
		t.Skip("helper process of TestSidecarAnswersAtTheHookPriorityClass")
	}
	class, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil || class != windows.NORMAL_PRIORITY_CLASS {
		t.Fatalf("child priority class %#x (%v), want normal", class, err)
	}
}

func TestSidecarRaisesEveryClassBelowTheHooks(t *testing.T) {
	for class, want := range map[uint32]bool{
		windows.IDLE_PRIORITY_CLASS:         true,
		windows.BELOW_NORMAL_PRIORITY_CLASS: true,
		windows.NORMAL_PRIORITY_CLASS:       true,
		windows.ABOVE_NORMAL_PRIORITY_CLASS: false,
		windows.HIGH_PRIORITY_CLASS:         false,
		windows.REALTIME_PRIORITY_CLASS:     false,
	} {
		if got := sidecarRaisesPriorityClass(class); got != want {
			t.Errorf("sidecarRaisesPriorityClass(%#x) = %v, want %v", class, got, want)
		}
	}
}
