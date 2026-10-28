// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
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

func TestOpenCodeRejectsOtherMajorsBeforeAnyWriteEvenWithDriftOverride(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "1")
	root := t.TempDir()
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = filepath.Join(root, "plugins", "defenseclaw.js")
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	if err := os.MkdirAll(filepath.Dir(OpenCodePluginPathOverride), 0o700); err != nil {
		t.Fatal(err)
	}
	const original = "existing installation remains untouched\n"
	if err := os.WriteFile(OpenCodePluginPathOverride, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, agentVersion := range []string{"1.18.33", "3.0.0"} {
		for _, mode := range []SetupOpts{
			{GuardrailMode: "observe"},
			{GuardrailMode: "action"},
			{ManagedEnterprise: true},
			{ManagedEnterprise: true, SecureClientHookDelivery: true},
		} {
			mode.AgentVersion = agentVersion
			mode.HookContractID = openCodeV2ContractID
			mode.DataDir = filepath.Join(root, "data")
			err := NewOpenCodeConnector().Setup(context.Background(), mode)
			if err == nil || !strings.Contains(err.Error(), "OpenCode V2 is required") {
				t.Fatalf("version %s with %+v: %v", agentVersion, mode, err)
			}
			body, readErr := os.ReadFile(OpenCodePluginPathOverride)
			if readErr != nil || string(body) != original {
				t.Fatal("refused setup changed the existing plugin")
			}
			if _, err := os.Lstat(mode.DataDir); !os.IsNotExist(err) {
				t.Fatalf("refused setup created the data directory: %v", err)
			}
		}
	}
}

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
const module = await import(pathToFileURL(path));
const plugin = module.default;
assert.deepEqual(Object.keys(module), ["default"]);
assert.equal(plugin.server, undefined);
assert.equal((await (await fetch(gateway + "/test/payloads")).json()), null, "import must not start any work");
const {contract} = await import(pathToFileURL(harness));
await contract(plugin, {
  reply: async (value) => { await fetch(gateway + "/test/reply", {method:"POST", body:JSON.stringify(value)}); },
  payloads: async () => (await fetch(gateway + "/test/payloads")).json(),
});`, plugin, harness, server.URL)
}

func TestOpenCodeV2GeneratedAdapter(t *testing.T) {
	for _, file := range []string{"hooks/opencode-plugin.js", "hooks/opencode-plugin-secure-client.js", "../../enterprisepolicy/opencode_managed_plugin.js"} {
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
		{"1.18.10", "", HookCompatibilityUnknown},
		{"1.18.33", "", HookCompatibilityUnknown},
		{"1.19.0", "", HookCompatibilityUnknown},
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
		if resolve.Status != HookCompatibilityKnown || resolve.Contract.ContractID != openCodeV2ContractID {
			t.Fatalf("every profile must admit the reviewed V2 contract: %+v", resolve)
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
			if got := openCodeToolCallLifecycle().ClassifyTerminalOutcome("opencode", "tool.execute.after", payload); got != tc.want {
				t.Fatalf("outcome %q, want %q", got, tc.want)
			}
		})
	}
}
