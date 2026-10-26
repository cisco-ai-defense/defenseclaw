// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	if output, ok := os.LookupEnv("TEST_COPILOT_FAILED_CHILD_OUTPUT"); ok {
		_, _ = io.Copy(io.Discard, os.Stdin)
		fmt.Print(output)
		os.Exit(7)
	}
}

func TestCopilotAdapterRejectsFailedChildOutput(t *testing.T) {
	shell, err := exec.LookPath("pwsh")
	if err != nil {
		shell, err = exec.LookPath("powershell.exe")
		if err != nil {
			t.Skip("PowerShell is not installed")
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := hookFS.ReadFile("hooks/copilot-hook.ps1")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderTemplate(string(source), templateData{
		FailMode: "closed", HookBinaryPS: strings.ReplaceAll(binary, "'", "''"), CopilotHookTimeoutMS: 10000,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "copilot.ps1")
	if err := os.WriteFile(path, []byte(rendered), 0600); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"preToolUse", "permissionRequest"} {
		for _, output := range []string{`{"permissionDecision":`, `{"permissionDecision":"allow"}`} {
			cmd := exec.Command(shell, "-NoProfile", "-NonInteractive", "-File", path, "-Event", event)
			cmd.Env = append(os.Environ(), "TEST_COPILOT_FAILED_CHILD_OUTPUT="+output)
			cmd.Stdin = strings.NewReader(`{}`)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("%s: %v: %s", event, err, stderr.String())
			}
			want := `{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}`
			if event == "permissionRequest" {
				want = `{"behavior":"deny","message":"DefenseClaw hook failed closed"}`
			}
			if stdout.String() != want {
				t.Errorf("%s forwarded failed output: %q; stderr=%s", event, stdout.String(), stderr.String())
			}
		}
	}
}
