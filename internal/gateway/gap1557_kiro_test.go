// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
)

func TestGAP1557KiroExecutePwshUsesPowerShellCommandReading(t *testing.T) {
	args := json.RawMessage(`{"command":"Get-ChildItem ."}`)
	command, tool := sandboxShellCommand(context.Background(), "kiro", "PreToolUse", "execute_pwsh", "shell", args)
	if len(command) == 0 || tool != "powershell" {
		t.Fatalf("Kiro command %s judged as %q, want powershell", command, tool)
	}
	command, tool = sandboxShellCommand(context.Background(), "kiro", "PreToolUse", "execute_bash", "shell", args)
	if len(command) == 0 || tool != "shell" {
		t.Fatalf("Kiro bash command %s judged as %q, want shell", command, tool)
	}
}
