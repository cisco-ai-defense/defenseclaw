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

const windowsLifecyclePriorityHelperEnv = "DEFENSECLAW_TEST_WINDOWS_LIFECYCLE_PRIORITY"

// GAP-0155: a Windows lifecycle run, and every program it starts, runs below
// normal priority, so the hooks keep the CPU they need; an idle class is
// kept. The check runs in a child process so the test binary keeps its own
// class.
func TestWindowsLifecycleRunYieldsTheCPUToTheHooks(t *testing.T) {
	if os.Getenv(windowsLifecyclePriorityHelperEnv) == "1" {
		windowsLifecycleYieldToHooks()
		windowsLifecycleYieldToHooks() // a second call keeps the class
		class, err := windows.GetPriorityClass(windows.CurrentProcess())
		if err != nil || class != windows.BELOW_NORMAL_PRIORITY_CLASS {
			t.Fatalf("lifecycle priority class %#x (%v), want below normal", class, err)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestWindowsLifecycleChildPriorityHelper$")
		child.Env = append(os.Environ(), windowsLifecyclePriorityHelperEnv+"=child")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("a program the lifecycle starts: %v\n%s", err, output)
		}
		if err := windows.SetPriorityClass(windows.CurrentProcess(), windows.IDLE_PRIORITY_CLASS); err != nil {
			t.Fatal(err)
		}
		windowsLifecycleYieldToHooks()
		if class, _ := windows.GetPriorityClass(windows.CurrentProcess()); class != windows.IDLE_PRIORITY_CLASS {
			t.Fatalf("an idle lifecycle run was raised to %#x", class)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsLifecycleRunYieldsTheCPUToTheHooks$", "-test.v")
	cmd.Env = append(os.Environ(), windowsLifecyclePriorityHelperEnv+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v\n%s", err, output)
	}
}

func TestWindowsLifecycleChildPriorityHelper(t *testing.T) {
	if os.Getenv(windowsLifecyclePriorityHelperEnv) != "child" {
		t.Skip("helper process of TestWindowsLifecycleRunYieldsTheCPUToTheHooks")
	}
	class, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil || class != windows.BELOW_NORMAL_PRIORITY_CLASS {
		t.Fatalf("child priority class %#x (%v), want below normal", class, err)
	}
}
