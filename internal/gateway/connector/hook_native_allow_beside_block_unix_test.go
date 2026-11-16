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

package connector

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1159: the gateway answers HTTP 200 with action block but a native
// PreToolUse object that allows. The agent acts on the object, so the shell
// Claude Code and Codex hooks must never print it: they answer the
// connector's own denial, in either fail mode (the native hook's
// nativeOutputAgrees, GAP-0950).
func TestShellHooksNeverPrintANativeAllowBesideABlock(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required")
	}
	allow := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"ok"}}`
	verdict := `{"action":"block","raw_action":"block","reason":"protected target","claude_code_output":` + allow + `,"codex_output":` + allow + `}`
	dir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(verdict))
	}))
	defer server.Close()
	if err := WriteHookScriptsWithToken(dir, strings.TrimPrefix(server.URL, "http://"), "tok-test"); err != nil {
		t.Fatalf("WriteHookScriptsWithToken: %v", err)
	}
	for _, tc := range []struct {
		script string
		args   []string
		stdin  string
	}{
		{"claude-code-hook.sh", nil, claudePreToolUse},
		{"codex-hook.sh", []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}, codexPreToolUse},
	} {
		for _, mode := range []string{"closed", "open"} {
			t.Run(tc.script+"/"+mode, func(t *testing.T) {
				dcHome := t.TempDir()
				installNativeGatewayForHookTest(t, dcHome, dir)
				cmd := exec.Command("bash", append([]string{filepath.Join(dir, tc.script)}, tc.args...)...)
				cmd.Env = append(os.Environ(), "HOME="+dcHome, "DEFENSECLAW_HOME="+dcHome, "DEFENSECLAW_FAIL_MODE="+mode)
				cmd.Stdin = strings.NewReader(tc.stdin)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				out := stdout.String()
				if strings.Contains(out, `"permissionDecision":"allow"`) {
					t.Fatalf("the hook printed the native allow beside a block: %s (stderr=%s)", out, stderr.String())
				}
				if !shellHookBlocked(err, out) {
					t.Fatalf("a block with a contradicting native object ran the tool: err=%v stdout=%q stderr=%s", err, out, stderr.String())
				}
			})
		}
	}
}
