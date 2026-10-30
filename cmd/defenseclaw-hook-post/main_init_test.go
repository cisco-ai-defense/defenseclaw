// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
)

// The per-user hook transport starts once per hook call. It links the
// command classifier (hookexec, hookpaths, actionfacts) without using it, so
// package init of those packages is paid on every call. actionfacts compiled
// all its patterns there: about 8.4 MB, a third of the CPU of a call, and on
// a busy host hook calls passed two seconds (GAP-1225, GAP-1283).
func TestHookPostStartupInitBudget(t *testing.T) {
	if os.Getenv("DEFENSECLAW_HOOK_POST_STARTUP_HELPER") == "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestHookPostStartupInitBudget$")
	cmd.Env = append(os.Environ(), "DEFENSECLAW_HOOK_POST_STARTUP_HELPER=1", "GODEBUG=inittrace=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hook-post startup helper: %v\n%s", err, output)
	}
	line := regexp.MustCompile(`(?m)^init github\.com/defenseclaw/defenseclaw/internal/actionfacts @[^\n]*?, ([0-9]+) bytes,`)
	match := line.FindSubmatch(output)
	if match == nil {
		t.Fatalf("no init trace for internal/actionfacts:\n%s", output)
	}
	allocated, err := strconv.ParseInt(string(match[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actionfacts package init: %d bytes", allocated)
	if allocated > 1<<20 {
		t.Fatalf("actionfacts package init allocates %d bytes on every hook-post start, want at most 1 MiB", allocated)
	}
}
