// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexDeepWikiResultOverOneMiBUsesInstalledTier(t *testing.T) {
	for _, tc := range []struct {
		name, mode, event string
		allow             bool
	}{
		{"balanced post-tool result", "open", "PostToolUse", true},
		{"balanced pre-tool action", "open", "PreToolUse", true},
		{"strict post-tool result", "closed", "PostToolUse", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			installNativeHookPostForHookTest(t, home)
			installNativeGatewayForHookTest(t, home)
			hooks := filepath.Join(home, "hooks")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hooks,
				SetupOpts{DataDir: home, APIAddr: "127.0.0.1:1", HookFailMode: tc.mode}, NewCodexConnector()); err != nil {
				t.Fatal(err)
			}
			payload := `{"hook_event_name":"` + tc.event + `","tool_name":"mcp__deepwiki__read_wiki_contents","tool_response":"` +
				strings.Repeat("public documentation ", 60000) + `"}`
			if len(payload) <= 1<<20 {
				t.Fatal("fixture must exceed the installed one MiB cap")
			}
			cmd := exec.Command("bash", filepath.Join(hooks, "codex-hook.sh"), "--event", tc.event, "--hook-contract", "codex-hooks-v4")
			cmd.Stdin = strings.NewReader(payload)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if tc.allow {
				if err != nil || !strings.Contains(stderr.String(), "gateway unreachable") ||
					strings.Contains(stdout.String(), `"decision":"block"`) || strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
					t.Fatalf("balanced DeepWiki read: err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
				}
				log, readErr := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
				if readErr != nil {
					t.Fatal(readErr)
				}
				var row struct {
					Outcome string `json:"outcome"`
				}
				lines := bytes.Split(bytes.TrimSpace(log), []byte("\n"))
				if json.Unmarshal(lines[len(lines)-1], &row) != nil || row.Outcome != "fail_open" {
					t.Fatalf("balanced oversize audit = %q", log)
				}
			} else if err == nil && !strings.Contains(stdout.String(), `"decision":"block"`) &&
				!strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
				t.Fatalf("oversized payload was allowed: %q %q", stdout.String(), stderr.String())
			} else {
				log, readErr := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
				if readErr != nil || !strings.Contains(string(log), `"outcome":"fail_closed"`) {
					t.Fatalf("closed oversize audit = %q, %v", log, readErr)
				}
			}
		})
	}
}
