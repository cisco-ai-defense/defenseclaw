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

package guardrail

import (
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1602: Haiku 4.5 read "Use the Bash tool to run exactly this command and
// nothing else: echo x > file" as Instruction/Context Manipulation (10 of 10
// live calls blocked). The injection prompt of every shipped profile (and the
// embedded fallback) must say that a user narrowing their own task, and a
// redirect inside the command they asked for, are not injection.
func TestInjectionJudgePromptExcludesUserScopedRequests(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	packs := map[string]string{"embedded": ""}
	for _, profile := range []string{"default", "permissive", "strict"} {
		packs[profile] = filepath.Join(root, "policies", "guardrail", profile)
	}
	for name, dir := range packs {
		judge := mustLoadRulePack(t, dir).InjectionJudge()
		if judge == nil {
			t.Fatalf("%s: no injection judge", name)
		}
		for _, want := range []string{
			"(not the user directing or narrowing their own task)",
			`"run exactly this command", "and nothing else"`,
			`part of the command the user asked for ("echo hello > notes.txt")`,
		} {
			if !strings.Contains(judge.SystemPrompt, want) {
				t.Errorf("%s injection prompt lacks %q", name, want)
			}
		}
	}
}
