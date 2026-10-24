// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCopilotAdapterRefusesInvalidEventBinding(t *testing.T) {
	found := false
	for _, engine := range []string{"powershell.exe", "pwsh"} {
		shell, err := exec.LookPath(engine)
		if err != nil {
			continue
		}
		found = true
		body, err := renderHookTemplate("copilot-hook.ps1", templateData{
			FailMode: "closed", HookBinaryPS: "missing-hook.exe", CopilotHookTimeoutMS: 1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(t.TempDir(), "copilot-hook.ps1")
		if err := os.WriteFile(script, body, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{nil, {"-Event"}, {"-Event", ""}, {"-Event", "futureEvent"}, {"-Event", "PreToolUse"}, {"-Event", "preToolUse"}} {
			t.Run(engine+"/"+strings.Join(args, " "), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, shell, append([]string{"-NoProfile", "-NonInteractive", "-File", script}, args...)...)
				// Binding is checked before stdin, home, or the missing launcher.
				cmd.Stdin = strings.NewReader(strings.Repeat(" ", (1<<20)+1))
				var out, diagnostic bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &diagnostic
				err := cmd.Run()
				var answer struct {
					PermissionDecision       string `json:"permissionDecision"`
					PermissionDecisionReason string `json:"permissionDecisionReason"`
					Behavior                 string `json:"behavior"`
					Message                  string `json:"message"`
				}
				decodeErr := json.Unmarshal(out.Bytes(), &answer)
				if len(args) == 2 && args[1] == "preToolUse" {
					if err != nil || decodeErr != nil || answer.PermissionDecision != "deny" || answer.Behavior != "" ||
						!strings.Contains(diagnostic.String(), "launcher is missing") {
						t.Fatalf("valid binding did not reach the launcher: err=%v stdout=%q stderr=%q", err, out.String(), diagnostic.String())
					}
					return
				}
				if err != nil || decodeErr != nil || answer.PermissionDecision != "deny" ||
					answer.Behavior != "deny" || !strings.Contains(answer.PermissionDecisionReason, "defenseclaw setup copilot") ||
					!strings.Contains(answer.Message, "defenseclaw setup copilot") {
					t.Fatalf("binding %q: err=%v stdout=%q stderr=%q", args, err, out.String(), diagnostic.String())
				}
			})
		}
	}
	if !found {
		t.Skip("PowerShell is unavailable")
	}
}
