// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"testing"
)

// The LLM proxy judges a tool call in a stand-in folder (proxyNeutralCWD): a
// relative nsenter working directory is relative to the caller's folder, not
// to that stand-in, so the child folder stays unknown there and the call keeps
// the verdict DefenseClaw 1.0.10 gave it. Resolving it under the stand-in
// placed alice/.defenseclaw/config.yaml under the temp folder and let the
// call through (rel-1-0-10:GAP-2188, a GAP-1482 regression on the llm route).
func TestGAP2188ProxyRelativeNSEnterFolderNotWeakerThanRel(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	t.Setenv("USERPROFILE", "/home/alice")
	rows := []struct {
		id, command string
		attack      bool
	}{
		{"wd-parent-state", "nsenter --target=1 --wd=.. sh -c ': >> alice/.defenseclaw/config.yaml'", true},
		{"wd-same-state", "nsenter --target=1 --wd=. sh -c ': >> .defenseclaw/config.yaml'", true},
		{"short-wd-parent-state", "nsenter --target=1 -w.. sh -c ': >> alice/.defenseclaw/config.yaml'", true},
		{"wrapped-wd-parent-state", `bash -c "nsenter --target=1 --wd=.. sh -c ': >> alice/.defenseclaw/config.yaml'"`, true},
		{"cd-up-wd-parent-state", "cd .. && nsenter --target=1 --wd=.. sh -c ': >> home/alice/.defenseclaw/config.yaml'", true},
		{"wd-parent-project", "nsenter --target=1 --wd=.. sh -c ': >> alice/proj/notes.txt'", false},
	}
	for _, pack := range []struct{ name, pack, want string }{
		{"default", "default", "alert"}, {"permissive", "permissive", "alert"}, {"strict", "strict", "block"},
	} {
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.cfg.RulePack = pack.pack
		installToolCallCorpusProfileConnector(t, proxy.connectorName(), pack.pack)
		for _, row := range rows {
			raw, _ := json.Marshal(map[string]string{"command": row.command})
			calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": "Bash", "arguments": string(raw)}}})
			action, severity := "allow", "NONE"
			var rules []string
			if res := proxy.inspectToolCalls(context.Background(), calls); res != nil {
				action, severity, rules = res.Action, res.Severity, res.RuleIDs
			}
			t.Logf("%s %s: %s/%s %v", pack.name, row.id, action, severity, rules)
			want := "allow"
			if row.attack {
				want = pack.want
			}
			if action != want {
				t.Errorf("%s %s: llm route %s/%s %v, want %s (1.0.10 verdict)", pack.name, row.id, action, severity, rules, want)
			}
		}
	}
}
