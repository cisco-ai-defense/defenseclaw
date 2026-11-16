// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// This is the PowerShell tool form in the GAP-0534 evidence case. Its Bash
// recovery parse prints a call that can be parsed back to itself.
const gap0534Command = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/.defenseclaw`

func TestGAP0534RecoveredParseFixedPoint(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	start := time.Now()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 8 {
		if reason := UnprovenProtectedWrite(gap0534Command, cwd, home); reason != "shell-parse-bound" {
			t.Fatalf("recovered parse reason = %q, want proof bound", reason)
		}
		payload, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "tool_name": "PowerShell", "cwd": cwd,
			"tool_input": map[string]string{"command": gap0534Command},
		})
		if err != nil {
			t.Fatal(err)
		}
		// Windows hookexec sends no Resolve write evidence. The bounded
		// parser check above still runs on every host.
		if hookWriteEvidenceHost() {
			if targets, ok := Decode(Resolve(payload)); !ok || targets[UnprovenReasonKey] != "shell-parse-bound" {
				t.Fatal("hook path resolver lost the unproven protected write")
			}
		}
	}
	runtime.ReadMemStats(&after)
	if used := after.TotalAlloc - before.TotalAlloc; used > 64<<20 {
		t.Fatalf("recovered parse allocated %d bytes", used)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("recovered parse took %s", elapsed)
	}
}
