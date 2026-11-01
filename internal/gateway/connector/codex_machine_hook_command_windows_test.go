// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The generated machine command hands the agent's stdin and stdout to the
// launcher and exits with the launcher's exit code: a fail-closed exit 2 and
// the launcher's JSON both reach Codex. (TestMain runs this test binary as
// the launcher in codex-machine-block mode.)
func TestWindowsCodexManagedHookCommandPropagatesExitCodeAndStdout(t *testing.T) {
	launcher, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(windowsCodexManagedHookCommand(launcher))
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Env = append(os.Environ(), cursorAdapterHelperMode+"=codex-machine-block")
	cmd.Stdin = strings.NewReader(`{"prompt":"codex-machine-probe"}`)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("machine command exit = %v, want 2; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"reason":"codex-machine-block"`) {
		t.Fatalf("machine command stdout = %q, want the launcher's decision", stdout.String())
	}
}
