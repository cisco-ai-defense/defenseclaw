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

// openCodeRunningSessionHarness loads the plugin once, as a running OpenCode
// session does, makes one tool call, rewrites config.yaml with the saved
// change the CLI makes, and makes a second call in the same process.
const openCodeRunningSessionHarness = `
import { pathToFileURL } from "node:url";
import { writeFileSync } from "node:fs";
const href = pathToFileURL(process.argv[1]).href;
const plugin = await (await import(href)).DefenseClaw({ directory: "", client: { tui: { showToast: async () => ({ data: true }) } } });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
const verdicts = [];
for (const [i, callID] of ["C1", "C2"].entries()) {
  if (i === 1) writeFileSync(process.env.DC_CONFIG_PATH, process.env.DC_CONFIG_NEXT);
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M" + i, callID }, { args: { command: "echo ok" } });
    verdicts.push("allow");
  } catch (error) {
    verdicts.push("block");
  }
}
console.log(JSON.stringify({ verdicts }));
`

// GAP-0970 / GAP-1408: an OpenCode session that is already running when the
// user saves a different outage mode follows the saved mode on its next call
// during the same outage: the plugin reads the mode when the call fails, not
// when it was loaded. Open then closed blocks the second call; closed then
// open (the default tier, nothing saved) lets it run.
func TestOpenCodeRunningSessionFollowsASavedOutageModeChange(t *testing.T) {
	nodeForTest(t)
	closed := outageDefaultTierConfig + "  hook_fail_mode: closed\n"
	for _, tc := range []struct {
		name, first, next string
		want              []string
	}{
		{"open then saved closed", outageDefaultTierConfig, closed, []string{"allow", "block"}},
		{"saved closed then default", closed, outageDefaultTierConfig, []string{"block", "allow"}},
		{"default then strict pack", outageDefaultTierConfig, outageStrictTierConfig, []string{"allow", "block"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			dataDir := filepath.Join(home, ".defenseclaw")
			token := filepath.Join(dataDir, "hooks", ".hook-opencode.token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			writeOutageTierConfig(t, dataDir, tc.first)
			body := renderPluginAssetForTest(t, "opencode-plugin.js", templateData{APIAddr: freeLoopbackAddrForOutageTest(t),
				TokenFileJS: javaScriptStringContent(token), FailMode: "closed"})
			path := filepath.Join(home, "defenseclaw.mjs")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", openCodeRunningSessionHarness, path)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0",
				"DC_CONFIG_PATH="+filepath.Join(dataDir, "config.yaml"), "DC_CONFIG_NEXT="+tc.next)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("node: %v\n%s", err, out)
			}
			var result struct {
				Verdicts []string `json:"verdicts"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
				t.Fatalf("harness output %q: %v", out, err)
			}
			if strings.Join(result.Verdicts, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("verdicts %v, want %v", result.Verdicts, tc.want)
			}
		})
	}
}
