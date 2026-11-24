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
	"os"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1782 (RV-OP2E2 P4): with the hook's stdout closed by its
// parent, the OpenShell sandbox Claude Code hook could not write the
// gateway's deny object, and the failed printf ended the hook with exit 1,
// which Claude Code reads as a non-blocking error: the call ran. Claude
// Code blocks on exit 2, as the Codex hook's failed write does (GAP-1769).
func TestGAP1782SandboxClaudeHookUnwritableDenyIsExitTwo(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	const closed = "/closed-stdout.sh"
	wrapper := "#!/bin/bash\nexec 1>&-\nexec " + shellSingleQuote(h.path(SandboxHookDir+"/claude-code-hook.sh")) + " \"$@\"\n"
	if err := os.WriteFile(h.path(closed), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	deny := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"nope"}}`
	for name, reply := range map[string][]string{
		"block verdict": {`200|{"action":"block","reason":"nope","claude_code_output":` + deny + `}`},
		"bare block":    {`200|{"action":"block","reason":"nope"}`},
		"ingress down":  {"exit:7", "exit:7"},
	} {
		t.Run(strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
			run := h.run(t, closed, nil, claudePreToolUse, map[string]string{SandboxTokenEnv: "tok"}, reply)
			if run.exitCode != 2 {
				t.Fatalf("exit %d stderr %q, want exit 2 when the deny cannot be written", run.exitCode, run.stderr)
			}
		})
	}
}
