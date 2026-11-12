// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// #1279: a lifecycle run (a config or bundle apply) yields the CPU to the
// gateway and the hook processes before it does any work.
func TestLifecycleRunYieldsBeforeItWorks(t *testing.T) {
	h := newTestHost(t, "linux")
	calls := 0
	h.env.Yield = func() { calls++ }
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if calls != 1 {
		t.Fatalf("Yield calls = %d, want 1", calls)
	}
	if env, err := NewEnv("linux", "1.0.0"); err != nil || env.Yield == nil {
		t.Fatalf("the production environment does not yield: %v", err)
	}
}

func TestYieldToHooksLowersEveryThread(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the lifecycle runs on Linux and macOS")
	}
	if os.Getenv("DC_TEST_YIELD_CHILD") == "1" {
		// yieldToHooks raises the priority to lifecycleNice and leaves an
		// already-lower one alone, so under `nice -n 15` every thread and
		// child stays at 15 (GAP-0678). Normally the start is 0 and the
		// expected value is exactly lifecycleNice.
		want := lifecycleNice
		if runtime.GOOS == "linux" {
			if raw, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0); err == nil && 20-raw > want {
				want = 20 - raw
			}
		}
		yieldToHooks()
		yieldToHooks() // a second call keeps the value
		if runtime.GOOS == "darwin" {
			if nice, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0); err != nil || nice < lifecycleNice {
				t.Fatalf("nice = %d, %v", nice, err)
			}
			return
		}
		entries, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			tid, _ := strconv.Atoi(entry.Name())
			if raw, err := syscall.Getpriority(syscall.PRIO_PROCESS, tid); err == nil && 20-raw < want {
				t.Fatalf("thread %d nice = %d, want at least %d", tid, 20-raw, want)
			}
		}
		out, err := exec.Command("sh", "-c", "cut -d' ' -f19 /proc/self/stat").Output()
		if err != nil || strings.TrimSpace(string(out)) != strconv.Itoa(want) {
			t.Fatalf("a child started after the yield has nice %q, want %d, %v", out, want, err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestYieldToHooksLowersEveryThread$")
	cmd.Env = append(os.Environ(), "DC_TEST_YIELD_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
