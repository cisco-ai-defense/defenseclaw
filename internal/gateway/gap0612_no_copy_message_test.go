// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0612NoCopyNextStep(t *testing.T) {
	for _, target := range []string{"~/.claude/settings.json", "~/.claude/settings.local.json", "/sandbox/work/.claude/settings.json", "/sandbox/work/.claude/settings.local.json"} {
		for _, tool := range []string{"Write", "Edit"} {
			t.Run(tool+"/"+target, func(t *testing.T) {
				input := map[string]any{"file_path": target, "content": "{}"}
				if tool == "Edit" {
					input = map[string]any{"file_path": target, "old_string": "/opt/a", "new_string": "/tmp/x"}
				}
				args, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				rule, note, _ := sandboxAgentHookConfigChange(context.Background(), trustedActionRequest{Connector: "claudecode", Input: actionfacts.Input{Tool: tool, Args: args, ActiveHome: "/sandbox", CWD: "/sandbox/work"}})
				if rule != agentHookConfigDisableRuleID || !strings.Contains(note, sandboxAgentHookNoBefore) {
					t.Fatalf("missing block/current-kit next step: %s %s", rule, note)
				}
				if strings.Contains(note, "change other keys with Edit") {
					t.Fatalf("refusal suggests another undecidable edit: %s", note)
				}
			})
		}
	}
}
