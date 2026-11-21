// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
)

// TestProxyReadOfWindowsCredentialPathAlertsFiveTiers (rel-1-0-10:GAP-0872):
// the /llm route reads a model reply's native Read of a C:\Users\<x> credential
// file as the hook route does: an alert in every pack but permissive (as rel
// answered), never the clean allow the neutral POSIX working folder gave.
func TestProxyReadOfWindowsCredentialPathAlertsFiveTiers(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	for _, p := range gap0437Packs {
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.cfg.RulePack = p.pack
		for _, path := range []string{`C:\Users\x\.aws\credentials`, `C:/Users/x/.aws/credentials`, `C:\Users\x\.docker\config.json`, `C:\Users\x\.netrc`, `C:\Users\x\.kube\config`} {
			args, _ := json.Marshal(map[string]string{"file_path": path})
			calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": "Read", "arguments": string(args)}}})
			v := proxy.inspectToolCalls(context.Background(), calls)
			if p.name != "permissive" && (v == nil || v.Action == "allow") {
				t.Errorf("%s: /llm Read of %s is a clean allow, want an alert", p.name, path)
			}
		}
	}
}
