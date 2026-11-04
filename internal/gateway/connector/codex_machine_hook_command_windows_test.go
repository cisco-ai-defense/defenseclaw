// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

// Under Constrained Language mode (WDAC/AppLocker script enforcement) the
// statements fall back to the call operator. A launcher that cannot start
// there must not turn into exit 0 (allow): $LASTEXITCODE is $null, so the
// script exits 1. A launcher that runs still has its exit code propagated.
func TestWindowsAwaitedHookStatementsConstrainedLanguageFailsClosed(t *testing.T) {
	run := func(t *testing.T, hookBinary string) (int, string) {
		t.Helper()
		script := "$ExecutionContext.SessionState.LanguageMode='ConstrainedLanguage'; " +
			decodePowerShellEncodedCommandForTest(t, windowsCodexManagedHookCommand(hookBinary))
		cmd := exec.Command(windowsSystemPowerShellExe(), "-NoLogo", "-NoProfile", "-NonInteractive",
			"-EncodedCommand", powershellEncodedCommand(script))
		cmd.Env = append(os.Environ(), cursorAdapterHelperMode+"=codex-machine-block")
		cmd.Stdin = strings.NewReader(`{"prompt":"codex-machine-probe"}`)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		err := cmd.Run()
		if err == nil {
			return 0, output.String()
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run constrained-language hook command: %v", err)
		}
		return exitErr.ExitCode(), output.String()
	}

	t.Run("missing launcher", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing", "defenseclaw-hook.exe")
		code, output := run(t, missing)
		if code == 0 {
			t.Fatalf("missing launcher exited 0 (allow); output:\n%s", output)
		}
		// The call operator, not Process.Start, reported the failure: the
		// constrained branch ran.
		if !strings.Contains(output, "CommandNotFoundException") {
			t.Fatalf("missing launcher did not fail through the constrained branch; output:\n%s", output)
		}
	})

	t.Run("running launcher", func(t *testing.T) {
		launcher, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		if code, output := run(t, launcher); code != 2 {
			t.Fatalf("constrained-language exit = %d, want the launcher's 2; output:\n%s", code, output)
		}
	})
}
