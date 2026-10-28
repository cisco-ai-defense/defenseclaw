// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The runtime lives under read-only /usr. Each shared logger must write to
// the workload's persistent data home, including neutral Stop answers.
func TestSandboxHookFailuresPersistInWorkloadHome(t *testing.T) {
	for _, tc := range sandboxHookCases() {
		t.Run(tc.connector+"/"+tc.script, func(t *testing.T) {
			h := newSandboxHookHarness(t, tc.provider, tc.version)
			result := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin,
				map[string]string{SandboxTokenEnv: "test binding token"}, []string{"exit:7", "exit:7"})
			if !tc.blocked(result) {
				t.Fatalf("outage must still block: %+v", result)
			}
			assertSandboxFailureLog(t, h, "closed", "fail_closed")
		})
	}
	for _, event := range []string{"Stop", "UserPromptSubmit"} {
		t.Run("codex/"+event, func(t *testing.T) {
			h := newSandboxHookHarness(t, &CodexConnector{}, "0.146.0")
			result := h.run(t, SandboxHookDir+"/codex-hook.sh",
				[]string{"--event", event, "--hook-contract", "codex-hooks-v4"},
				`{"hook_event_name":"`+event+`","session_id":"s1","turn_id":"t1","prompt":"hi"}`,
				map[string]string{SandboxTokenEnv: "test binding token"}, []string{"exit:7", "exit:7"})
			if event == "Stop" {
				if result.exitCode != 0 || !strings.Contains(result.stderr, "not blocking") {
					t.Fatalf("Stop must allow and explain the outage: %+v", result)
				}
				assertSandboxFailureLog(t, h, "open", "fail_open")
			} else {
				if result.exitCode != 2 {
					t.Fatalf("prompt must block: %+v", result)
				}
				assertSandboxFailureLog(t, h, "closed", "fail_closed")
			}
		})
	}
}

func assertSandboxFailureLog(t *testing.T, h *sandboxHookHarness, mode, outcome string) {
	t.Helper()
	logPath := h.path(SandboxHomeDir + "/.defenseclaw/logs/hook-failures.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("no persistent workload hook failure log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one failure per invocation, got %q", data)
	}
	var row map[string]string
	if err := json.Unmarshal(data, &row); err != nil {
		t.Fatal(err)
	}
	if row["fail_mode"] != mode || row["outcome"] != outcome || row["category"] != "transport" {
		t.Fatalf("failure log must describe the actual answer: %s", data)
	}
	for path, want := range map[string]os.FileMode{logPath: 0o600, filepath.Dir(logPath): 0o700} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("private failure log permissions: %s: %v, want %o", path, err, want)
		}
	}
	if _, err := os.Stat(h.path(SandboxLibDir + "/logs/hook-failures.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("sandbox runtime must not be the log destination: %v", err)
	}
}
