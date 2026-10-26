// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1236, GAP-1898: a per-user OpenCode or Amp plugin answered every failed
// check that was not an outage with "per-user gateway peer unverified": a
// helper whose connected-peer proof raced the gateway once (the retry runs),
// and a gateway answer the plugin refused for a repeated key (the real
// cause). The plugin tries a failed helper once more, names the cause of a
// block and records it in hook-failures.jsonl.
func TestPerUserPluginNamesTheCauseOfAFailedCheckAndRetriesTheHelperOnce(t *testing.T) {
	nodeForTest(t)
	const allow = `{"status":200,"body":"{\"action\":\"allow\",\"raw_action\":\"allow\",\"severity\":\"NONE\",\"hook_output\":{}}"}`
	const repeated = `{"status":200,"body":"{\"action\":\"block\",\"action\":\"allow\"}"}`
	for _, plugin := range []struct{ asset, name, connector, harness string }{
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness},
	} {
		for _, tc := range []struct {
			name, helper, wantVerdict string
			wantRow                   bool
		}{
			{"a peer proof that raced once", "if [ ! -e \"$HOME/raced\" ]; then : > \"$HOME/raced\"; echo 'defenseclaw-gateway hook-post: connected peer proof raced the gateway' >&2; exit 1; fi; printf '%s' '" + allow + "'", "allow", false},
			{"a helper that keeps failing", "echo 'defenseclaw-gateway hook-post: dccert peer proof failed' >&2; exit 1", "dccert peer proof failed", true},
			{"a repeated-key answer", "printf '%s' '" + repeated + "'", "repeated key", true},
		} {
			t.Run(plugin.connector+"/"+tc.name, func(t *testing.T) {
				home := t.TempDir()
				binDir := filepath.Join(home, ".local", "bin")
				if err := os.MkdirAll(binDir, 0o700); err != nil {
					t.Fatal(err)
				}
				fake := "#!/bin/sh\nif [ \"$1\" = hook-post ]; then cat >/dev/null; " + tc.helper + "; exit 0; fi\nif [ \"$1\" = hook-outage-mode ]; then printf 'open\\n'; exit 0; fi\nexit 1\n"
				if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(fake), 0o700); err != nil {
					t.Fatal(err)
				}
				dataDir := filepath.Join(home, ".defenseclaw")
				writeOutageTierConfig(t, dataDir, outageDefaultTierConfig)
				token := filepath.Join(dataDir, "hooks", ".hook-"+plugin.connector+".token")
				if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(token), ".gateway-helper"), []byte(filepath.Join(binDir, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				body := renderPluginAssetForTest(t, plugin.asset, templateData{APIAddr: freeLoopbackAddrForOutageTest(t),
					TokenFileJS: javaScriptStringContent(token), FailMode: "closed"})
				path := filepath.Join(home, plugin.name)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", plugin.harness, path)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
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
				if tc.wantVerdict == "allow" {
					if result.Verdict != "allow" {
						t.Fatalf("verdict %q, want the retried check's allow", result.Verdict)
					}
				} else if !strings.HasPrefix(result.Verdict, "block:") || !strings.Contains(result.Verdict, tc.wantVerdict) ||
					strings.Contains(result.Verdict, "peer unverified") {
					t.Fatalf("verdict %q, want a block that names %q", result.Verdict, tc.wantVerdict)
				}
				rows := hookFailureRecords(t, dataDir)
				if tc.wantRow && (len(rows) != 1 || rows[0]["outcome"] != "fail_closed" || !strings.Contains(rows[0]["reason"], tc.wantVerdict)) {
					t.Fatalf("hook-failures rows %+v, want one fail_closed row naming the cause", rows)
				}
				if !tc.wantRow && len(rows) != 0 {
					t.Fatalf("hook-failures rows %+v, want none", rows)
				}
			})
		}
	}
}

// GAP-1881: a per-user plugin rendered by a gateway outside ~/.local/bin runs
// that gateway (the install's own location); the ~/.local/bin gateway keeps
// the .gateway-helper record (empty).
func TestPerUserPluginUnixGatewayBinaryIsTheInstallsGateway(t *testing.T) {
	home := "/home/dev"
	for _, tc := range []struct{ gateway, want string }{
		{"/home/dev/.local/bin/defenseclaw-gateway", ""},
		{"/home/dev/gvalt/bin/defenseclaw-gateway", "/home/dev/gvalt/bin/defenseclaw-gateway"},
		{"/tmp/go-build1/connector.test", ""},
		{"defenseclaw-gateway", ""},
	} {
		if got := perUserPluginUnixGatewayBinary(home, tc.gateway); got != tc.want {
			t.Fatalf("perUserPluginUnixGatewayBinary(%q) = %q, want %q", tc.gateway, got, tc.want)
		}
	}
}
