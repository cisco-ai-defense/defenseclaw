// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/opencodebridge"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestOpenCodeV2Contract(t *testing.T) {
	var mu sync.Mutex
	reply := json.RawMessage(`{"action":"allow","mode":"action"}`)
	var payloads []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/test/reply":
			reply, _ = io.ReadAll(r.Body)
		case "/test/payloads":
			_ = json.NewEncoder(w).Encode(payloads)
		default:
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("payload: %v", err)
			}
			payloads = append(payloads, payload)
			_, _ = w.Write(reply)
		}
	}))
	defer server.Close()
	plugin := writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", openCodePluginTestData(t, server))
	harness, err := filepath.Abs("../../opencodebridge/testdata/contract.mjs")
	if err != nil {
		t.Fatal(err)
	}
	runNodeHarness(t, `
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
const [path, harness, gateway] = process.argv.slice(1);
const {default: plugin, DefenseClaw} = await import(pathToFileURL(path));
assert.equal(plugin.server, DefenseClaw);
assert.equal((await (await fetch(gateway + "/test/payloads")).json()), null, "import must not start any work");
const {contract} = await import(pathToFileURL(harness));
await contract(plugin, {
  reply: async (value) => { await fetch(gateway + "/test/reply", {method:"POST", body:JSON.stringify(value)}); },
  payloads: async () => (await fetch(gateway + "/test/payloads")).json(),
});`, plugin, harness, server.URL)
}

func TestOpenCodeV2GeneratedAdapter(t *testing.T) {
	for _, file := range []string{"hooks/opencode-plugin.js", "../../enterprisepolicy/opencode_managed_plugin.js"} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), opencodebridge.Adapter) {
			t.Fatalf("%s is stale: run python3 scripts/generate_opencode_plugins.py", file)
		}
	}
}

func TestOpenCodeV2OutageAndCredentialFailures(t *testing.T) {
	for _, tc := range []struct {
		name, mode              string
		missingToken, wantBlock bool
		nativeStatus            int
	}{
		{"closed outage", "closed", false, true, 7},
		{"open outage", "open", false, false, 7},
		{"closed missing credential", "closed", true, true, 0},
		{"open missing credential", "open", true, true, 0},
		{"open unverified native peer", "open", false, true, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "")
			server := openCodeStubGateway(t)
			data := openCodePluginTestData(t, server)
			data.FailMode = tc.mode
			data.OutageFailMode = tc.mode
			if tc.missingToken {
				data.TokenFileJS = javaScriptStringContent(filepath.Join(t.TempDir(), "missing.token"))
			} else {
				server.Close()
			}
			plugin := writeRenderedPlugin(t, "opencode-plugin.js", "plugin.mjs", data)
			if tc.nativeStatus != 0 {
				// Keep the installed transport and mock only the native
				// process result: exit 7 is a classified outage; other
				// failures must stay closed even when outage mode is open.
				binary := filepath.Join(testenv.PrivateTempDir(t), "bin", "defenseclaw-gateway.exe")
				if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(binary, []byte("fixture native process"), 0o700); err != nil {
					t.Fatal(err)
				}
				data.GatewayBinaryJS = javaScriptStringContent(binary)
				if err := os.WriteFile(plugin, []byte(renderOpenCodePluginTemplate(t, data)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			lines := runNodeHarness(t, `
import {pathToFileURL} from "node:url";
import childProcess from "node:child_process";
import {syncBuiltinESMExports} from "node:module";
const nativeStatus = Number(process.argv[2]);
if (nativeStatus) {
 childProcess.execFileSync = () => { throw Object.assign(new Error("fixture native process result"), {status:nativeStatus}); };
 syncBuiltinESMExports();
}
const {default: plugin} = await import(pathToFileURL(process.argv[1]));
const location = {directory:"/work"}; let before;
const cleanup = await plugin.setup({location,
 session:{get:async({sessionID})=>({id:sessionID,location})},mcp:{list:async()=>[]},
 tool:{hook:async(name,cb)=>{if(name==="execute.before") before=cb;return{dispose:async()=>{}}}},
 event:{subscribe:async function*(){}}
});
try { await before({tool:"shell",input:{command:"echo test"},id:"call_1",sessionID:"ses_1"}); console.log("allow"); }
catch { console.log("block"); }
await cleanup();`, plugin, fmt.Sprint(tc.nativeStatus))
			if got := lines[len(lines)-1] == "block"; got != tc.wantBlock {
				t.Fatalf("block=%v, want %v", got, tc.wantBlock)
			}
		})
	}
}

func TestOpenCodeV2VersionSelection(t *testing.T) {
	for _, tc := range []struct{ version, contract, status string }{
		{"1.18.10", "opencode-hooks-v1", HookCompatibilityKnown},
		{"1.18.33", "opencode-hooks-v1", HookCompatibilityKnown},
		{"1.19.0", "opencode-hooks-v1", HookCompatibilityKnown},
		{"2.0.0", openCodeV2ContractID, HookCompatibilityKnown},
		{"2.1.4", openCodeV2ContractID, HookCompatibilityKnown},
		{"2.2.0", openCodeV2ContractID, HookCompatibilityKnown},
		{"3.0.0", "", HookCompatibilityUnknown},
		{"vgit.5bba024", "", HookCompatibilityUnknown},
	} {
		t.Run(tc.version, func(t *testing.T) {
			for _, goos := range []string{"linux", "darwin", "windows"} {
				got := resolveHookContractForOSMode("opencode", tc.version, goos, false)
				if got.Contract.ContractID != tc.contract || got.Status != tc.status {
					t.Fatalf("%s: %+v", goos, got)
				}
			}
		})
	}
	for _, resolve := range []HookContractResolution{
		ResolveHookContractStrict("opencode", "2.1.4"),
		resolveHookContractForOptions("opencode", SetupOpts{AgentVersion: "2.1.4", ManagedEnterprise: true}),
	} {
		if resolve.Status != HookCompatibilityUnknown {
			t.Fatalf("pinned Secure Client profile must not admit v2: %+v", resolve)
		}
	}
	if spec, ok := CorrelationSpecForConnector("opencode", openCodeV2ContractID); !ok || spec.ProfileVersion != CorrelationProfileOpenCodeV2 {
		t.Fatalf("v2 correlation: %+v, %v", spec, ok)
	}
}

func TestOpenCodeV2TerminalOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, tool, result string
		want               ToolLifecycleOutcome
	}{
		{"shell success", "shell", `{"opencode_v2_status":"completed","output":{"exit":0,"status":"completed"}}`, ToolLifecycleOutcomeSuccess},
		{"shell failure", "shell", `{"opencode_v2_status":"completed","output":{"exit":1}}`, ToolLifecycleOutcomeFailure},
		{"background shell", "shell", `{"opencode_v2_status":"completed","output":{"status":"running"}}`, ToolLifecycleOutcomeUnknown},
		{"shell timeout", "shell", `{"opencode_v2_status":"completed","output":{"timeout":true}}`, ToolLifecycleOutcomeFailure},
		{"missing exit", "shell", `{"opencode_v2_status":"completed","output":{"output":"text"}}`, ToolLifecycleOutcomeUnknown},
		{"tool error", "read", `{"opencode_v2_status":"error","error":{"message":"missing"}}`, ToolLifecycleOutcomeFailure},
		{"content", "read", `{"opencode_v2_status":"completed","content":[{"type":"text","text":"data"}]}`, ToolLifecycleOutcomeSuccess},
		{"structured output", "corp_docs_search", `{"opencode_v2_status":"completed","output":{"found":true}}`, ToolLifecycleOutcomeSuccess},
		{"missing result", "read", `{"opencode_v2_status":"unknown"}`, ToolLifecycleOutcomeUnknown},
		{"malformed result", "read", `{"opencode_v2_status":"completed","content":42}`, ToolLifecycleOutcomeUnknown},
		{"legacy shape", "read", `{"output":"v1"}`, ToolLifecycleOutcomeUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var result map[string]any
			if err := json.Unmarshal([]byte(tc.result), &result); err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{"tool_name": tc.tool, "tool_response": result}
			if got := openCodeV2ToolCallLifecycle().ClassifyTerminalOutcome("opencode", "tool.execute.after", payload); got != tc.want {
				t.Fatalf("outcome %q, want %q", got, tc.want)
			}
		})
	}
}
