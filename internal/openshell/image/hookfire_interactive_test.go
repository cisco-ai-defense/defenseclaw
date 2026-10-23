// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package image

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runPTYDriver runs the probe's pty driver against a stand-in TUI, a bash
// script with this body, and returns the driver's output, what it logged
// of the TUI and its error.
func runPTYDriver(t *testing.T, body string) (string, string, error) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	tui := filepath.Join(dir, "tui")
	if err := os.WriteFile(tui, []byte("#!/bin/bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "out")
	cmd := exec.Command(python, "-I", "-S", "-c", ptyDriver, "20", "hello probe", interactiveDoneText, "/exit", tui)
	cmd.Env = append(os.Environ(), "DC_HOOKFIRE_OUT="+logPath)
	out, err := cmd.CombinedOutput()
	logged, _ := os.ReadFile(logPath)
	return string(out), string(logged), err
}

func wantDriverExit(t *testing.T, err error, out string, code int) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
		t.Fatalf("driver = %v, want the TUI's exit status %d\n%s", err, code, out)
	}
}

// TestPTYDriverTypesThePromptAndQuits runs the probe's pty driver against a
// stand-in TUI: it must wait for the prompt, type the scenario prompt, wait
// for the closing text across line breaks, type quit and pass on the exit
// status.
func TestPTYDriverTypesThePromptAndQuits(t *testing.T) {
	out, logged, err := runPTYDriver(t, "printf 'ready> '\nIFS= read -r line\n[ \"$line\" = \"hello probe\" ] || exit 3\n"+
		"printf 'working\\r\\nDone: the marker\\r\\n file was written.\\r\\n> '\nIFS= read -r q\n[ \"$q\" = /exit ] && exit 7\nexit 4\n")
	wantDriverExit(t, err, out, 7)
	if !strings.Contains(logged, "ready> ") || !strings.Contains(logged, "file was written") {
		t.Fatalf("driver log = %q", logged)
	}
}

// The driver exited 125 for a TUI that had quit (a loaded Linux host): the
// terminal closes as the TUI exits, a moment before the kernel lets its
// status be collected, and the driver's wait counted reads of the closed
// terminal, which return at once, rather than time. A TUI that lets go of
// its terminal a second before it exits still has its own status passed
// on, not a signal's.
func TestPTYDriverWaitsForTheStatusAfterTheTerminalCloses(t *testing.T) {
	out, _, err := runPTYDriver(t, "printf 'ready> '\nIFS= read -r line\n"+
		"printf 'Done: the marker file was written.\\r\\n> '\nIFS= read -r q\n"+
		"exec </dev/null >/dev/null 2>&1\nsleep 1\n[ \"$q\" = /exit ] && exit 7\nexit 4\n")
	wantDriverExit(t, err, out, 7)
}
