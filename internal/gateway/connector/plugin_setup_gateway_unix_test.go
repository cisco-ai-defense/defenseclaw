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

// GAP-1847: a per-user OpenCode or Amp plugin rendered with the gateway of
// its install (DC_GATEWAY_BINARY, native Windows Setup's InstallRoot\bin)
// posts through that gateway and needs no ~/.local/bin. The control renders
// "" on the same layout: the plugin looks only in ~/.local/bin, finds no
// gateway and fails closed on a benign call, which is the defect. The
// connected-peer check is the real native gateway's (hook-post).
func TestPerUserPluginsPostThroughTheRenderedInstallGateway(t *testing.T) {
	nodeForTest(t)
	for _, plugin := range []struct{ asset, name, connector, harness string }{
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness},
	} {
		for _, rendered := range []bool{true, false} {
			name := plugin.connector + "/install gateway"
			if !rendered {
				name = plugin.connector + "/control: no rendered gateway"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow","mode":"observe","hook_output":{"decision":"allow"}}`))
				}))
				defer server.Close()
				scratch := t.TempDir()
				installNativeGatewayForHookTest(t, scratch)
				setupBin := filepath.Join(t.TempDir(), "Programs", "DefenseClaw", "bin")
				if err := os.MkdirAll(setupBin, 0o700); err != nil {
					t.Fatal(err)
				}
				gateway := filepath.Join(setupBin, "defenseclaw-gateway")
				if err := os.Link(filepath.Join(scratch, ".local", "bin", "defenseclaw-gateway"), gateway); err != nil {
					t.Fatal(err)
				}
				home := t.TempDir() // like a Setup install: no ~/.local/bin
				token := filepath.Join(home, ".defenseclaw", "hooks", ".hook-"+plugin.connector+".token")
				if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				data := templateData{APIAddr: strings.TrimPrefix(server.URL, "http://"),
					TokenFileJS: javaScriptStringContent(token), FailMode: "closed", OutageFailMode: "open"}
				if rendered {
					data.GatewayBinaryJS = javaScriptStringContent(gateway)
				}
				path := filepath.Join(home, plugin.name)
				if err := os.WriteFile(path, []byte(renderPluginAssetForTest(t, plugin.asset, data)), 0o600); err != nil {
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
				if allowed := result.Verdict == "allow"; allowed != rendered {
					t.Fatalf("verdict %q (%s), want allowed=%v", result.Verdict, out, rendered)
				}
			})
		}
	}
}
