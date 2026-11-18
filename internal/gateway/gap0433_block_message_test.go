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

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// substrate-1 GAP-0433 (lead ruling for 1.0.10): the actor blocks a rewrite
// of its registered ~/.claude/settings.json that drops DefenseClaw's hook
// entries, even where the laptop would allow it, because the gateway cannot
// read the actor's copy. The block must say why (the hooks are managed by
// root-owned settings in an actor) and what to do instead.
func TestGAP0433ActorHookFileBlockSaysWhatToDo(t *testing.T) {
	args, err := json.Marshal(map[string]any{"file_path": "~/.claude/settings.json", "content": `{"permissions":{"allow":["Bash(ls)"]}}`})
	if err != nil {
		t.Fatal(err)
	}
	ruleID, note, target := sandboxAgentHookConfigChange(context.Background(), trustedActionRequest{
		Connector: "claudecode",
		Input:     actionfacts.Input{Tool: "Write", Args: args, ActiveHome: "/sandbox", CWD: "/sandbox/work"},
	})
	if ruleID != agentHookConfigDisableRuleID || target != "/sandbox/.claude/settings.json" {
		t.Fatalf("rule %q target %q note %q, want %s on /sandbox/.claude/settings.json", ruleID, target, note, agentHookConfigDisableRuleID)
	}
	for _, want := range []string{"managed by root-owned settings", "change other keys with Edit", "ask your administrator"} {
		if !strings.Contains(note, want) {
			t.Fatalf("block note %q does not say %q", note, want)
		}
	}
}
