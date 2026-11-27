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
// relative chroot root is relative to the caller's folder, not to that
// stand-in, so the child root stays unknown there and the call keeps the
// verdict of an unknown folder, as the nsenter --wd twin does (GAP-2188).
// Resolving it under the stand-in placed alice/.defenseclaw/config.yaml under
// the temp folder and let the call through (rel-1-0-10:GAP-2189). The
// here-document spelling of the same call (chroot .. sh <<E) is the
// unresolved-root here-document class of GAP-2132, judged the same on every
// route and build (allow at 1.0.10, rel and here), and is not pinned here.
func TestGAP2189ProxyRelativeChrootRootNotResolvedAtStandIn(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	t.Setenv("USERPROFILE", "/home/alice")
	rows := []struct {
		id, command string
		attack      bool
	}{
		{"root-parent-state", "chroot .. sh -c ': >> alice/.defenseclaw/config.yaml'", true},
		{"root-same-state", "chroot . sh -c ': >> .defenseclaw/config.yaml'", true},
		{"wrapped-root-parent-state", `bash -c "chroot .. sh -c ': >> alice/.defenseclaw/config.yaml'"`, true},
		{"cd-up-root-parent-state", "cd .. && chroot .. sh -c ': >> home/alice/.defenseclaw/config.yaml'", true},
		{"root-parent-project", "chroot .. sh -c ': >> alice/proj/notes.txt'", false},
		{"root-absolute-project", "chroot / sh -c ': >> home/alice/proj/notes.txt'", false},
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
				t.Errorf("%s %s: llm route %s/%s %v, want %s", pack.name, row.id, action, severity, rules, want)
			}
		}
	}
}
