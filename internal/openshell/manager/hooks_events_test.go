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

package manager

import "testing"

// TestIsToolEventEverySandboxHarness counts each sandboxed harness's
// pre-tool event once, and nothing else.
func TestIsToolEventEverySandboxHarness(t *testing.T) {
	for _, event := range []string{
		"PreToolUse",          // Claude Code, Codex, Devin
		"preToolUse",          // Copilot CLI, Cursor Agent, Kiro CLI
		"tool.execute.before", // OpenCode
		"tool.call",           // Amp
		"pre_tool_call",
	} {
		if !isToolEvent(event) {
			t.Errorf("%s is not counted as a tool call", event)
		}
	}
	for _, event := range []string{
		"PostToolUse", "postToolUse", "tool.execute.after", "tool.result", "beforeShellExecution", "UserPromptSubmit", "",
	} {
		if isToolEvent(event) {
			t.Errorf("%s is counted as a tool call", event)
		}
	}
}
