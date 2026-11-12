// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// A tracer can report its own failure while the allowed hook remains sound.
// The program ceiling still needs forty complete traces in that case.
func TestWarmRegisteredClaudeHookKeepsCountingAfterTracerFailure(t *testing.T) {
	realStrace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace unavailable")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "failed-once")
	wrapper := filepath.Join(dir, "strace")
	script := "#!/bin/sh\n" +
		"case \"$*\" in */dev/null*) exec " + strconv.Quote(realStrace) + " \"$@\";; esac\n" +
		"if [ ! -e " + strconv.Quote(marker) + " ]; then\n" +
		"  : > " + strconv.Quote(marker) + "\n" +
		"  echo 'strace: ptrace(PTRACE_LISTEN,pid:0,sig:0): Input/output error' >&2\n" +
		"  exit 1\n" +
		"fi\nexec " + strconv.Quote(realStrace) + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	TestWarmRegisteredClaudeHookRunsAtMostEightPrograms(t)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("tracer failure was not exercised: %v", err)
	}
}
