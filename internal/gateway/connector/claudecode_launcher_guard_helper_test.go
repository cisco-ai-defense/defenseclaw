// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// guardPassthroughLauncherName is the file name under which a copy of the test
// binary answers as a real launcher that runs (see
// answerAsGuardPassthroughLauncher). A test binary is never named so.
const guardPassthroughLauncherName = "defenseclaw-hook.exe"

const (
	// guardLauncherModeEnv selects the answer of the launcher copy: empty
	// prints the arguments and copies stdin, "review" answers like the review
	// fixture of the GAP-0322 tests.
	guardLauncherModeEnv = "DEFENSECLAW_TEST_LAUNCHER_MODE"
	// guardLauncherExitEnv is the exit code of the empty mode (default 7).
	guardLauncherExitEnv = "DEFENSECLAW_TEST_LAUNCHER_EXIT"
)

// answerAsGuardPassthroughLauncher makes a copy of this test binary named
// defenseclaw-hook.exe behave as a launcher that runs, on Windows, where a
// shell script is not an executable. By default it prints its arguments, each
// followed by "|", copies its stdin to stdout and exits 7 (or the code in
// guardLauncherExitEnv). It answers only when guardLauncherModeEnv is set.
// In "review" mode it reads one line: "protected" and "down" are denied
// (exit 2, "review denied" on stderr), "ordinary" is allowed (exit 0, an
// allow answer), anything else exits 2.
func answerAsGuardPassthroughLauncher() {
	// Only a test that sets guardLauncherModeEnv (to "" or "review") asks for
	// this answer: other tests copy the test binary as defenseclaw-hook.exe
	// too (the Hermes execution probe, the Copilot adapter install window)
	// and need TestMain's own dispatch, not exit 7.
	mode, asked := os.LookupEnv(guardLauncherModeEnv)
	if !asked || len(os.Args) < 2 || os.Args[1] != "hook" ||
		!strings.EqualFold(filepath.Base(os.Args[0]), guardPassthroughLauncherName) {
		return
	}
	if mode == "review" {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		switch strings.TrimSpace(line) {
		case "protected", "down":
			fmt.Fprintln(os.Stderr, "review denied")
			os.Exit(2)
		case "ordinary":
			fmt.Println(`{"action":"allow"}`)
			os.Exit(0)
		}
		os.Exit(2)
	}
	fmt.Print(strings.Join(os.Args[1:], "|") + "|")
	_, _ = io.Copy(os.Stdout, os.Stdin)
	code := 7
	if want, err := strconv.Atoi(os.Getenv(guardLauncherExitEnv)); err == nil {
		code = want
	}
	os.Exit(code)
}

// copyTestBinaryAsLauncher installs a copy of this test binary as
// <dir>/defenseclaw-hook.exe and returns its path.
func copyTestBinaryAsLauncher(t *testing.T, dir string) string {
	t.Helper()
	// The copy answers as the launcher only while guardLauncherModeEnv is set
	// (the empty mode unless the test picks one).
	if _, ok := os.LookupEnv(guardLauncherModeEnv); !ok {
		t.Setenv(guardLauncherModeEnv, "")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, guardPassthroughLauncherName)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, data, 0o700); err != nil {
		t.Fatal(err)
	}
	return launcher
}

// writePassthroughLauncher installs the launcher the guard test runs: a copy
// of the test binary on Windows, a shell script elsewhere. Both print their
// arguments, each followed by "|", then copy stdin and exit 7.
func writePassthroughLauncher(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return copyTestBinaryAsLauncher(t, dir)
	}
	launcher := filepath.Join(dir, guardPassthroughLauncherName)
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nprintf '%s|' \"$@\"\ncat\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return launcher
}
