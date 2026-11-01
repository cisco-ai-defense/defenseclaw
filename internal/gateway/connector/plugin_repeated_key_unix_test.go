// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1007: JavaScript's JSON.parse keeps the last copy of a repeated key,
// so an in-agent plugin read {"action":"block","action":"allow"} as allow
// while the native and shell hooks refuse it. A running gateway's ambiguous
// answer is never an outage: the OpenCode and Amp plugins block it in every
// tier, here the outage-open default tier. The controls prove the same
// keys in separate objects, and quotes or braces inside strings, still pass.
func TestPerUserPluginsRefuseARepeatedKeyInTheAnswer(t *testing.T) {
	nodeForTest(t)
	answers := []struct {
		name, body string
		allowed    bool
	}{
		{"control: clean allow", `{"action":"allow","raw_action":"allow","mode":"observe","hook_output":{"decision":"allow"}}`, true},
		{"control: same key in separate objects", `{"action":"allow","mode":"observe","hook_output":{"action":"allow","decision":"allow"},"rules":[{"id":"a"},{"id":"b"}]}`, true},
		{"control: quotes, braces and commas in strings", `{"action":"allow","reason":"a \"{\" , \"action\":\"block\" }","mode":"observe","hook_output":{"decision":"allow"}}`, true},
		{"repeated action, allow last", `{"action":"block","action":"allow","mode":"observe","hook_output":{"decision":"allow"}}`, false},
		{"repeated action, escaped spelling", `{"action":"block","act\u0069on":"allow","mode":"observe","hook_output":{"decision":"allow"}}`, false},
		{"repeated nested decision", `{"action":"allow","mode":"observe","hook_output":{"decision":"deny","decision":"allow"}}`, false},
		{"repeated key in an array element", `{"action":"allow","mode":"observe","hook_output":{"decision":"allow"},"rules":[{"id":"a","id":"b"}]}`, false},
	}
	for _, plugin := range []struct{ asset, name, connector, harness string }{
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness},
	} {
		for _, answer := range answers {
			t.Run(plugin.connector+"/"+answer.name, func(t *testing.T) {
				t.Parallel()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(answer.body))
				}))
				defer server.Close()
				home := t.TempDir()
				token := filepath.Join(home, ".defenseclaw", "hooks", ".hook-"+plugin.connector+".token")
				if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
					t.Fatal(err)
				}
				// The plugin posts through the helper its hook directory
				// records (.gateway-helper), as a rendered install has.
				installNativeGatewayForHookTest(t, home, filepath.Dir(token))
				if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				body := renderPluginAssetForTest(t, plugin.asset, templateData{APIAddr: strings.TrimPrefix(server.URL, "http://"),
					TokenFileJS: javaScriptStringContent(token), FailMode: "closed"})
				path := filepath.Join(home, plugin.name)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", withOpenCodeV2Fixture(t, plugin.harness), path)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("node: %v\n%s", err, out)
				}
				var result struct {
					Verdict string `json:"verdict"`
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
					t.Fatalf("harness output %q: %v", out, err)
				}
				if (result.Verdict == "allow") != answer.allowed {
					t.Fatalf("verdict %q, want allowed=%v", result.Verdict, answer.allowed)
				}
			})
		}
	}
}
