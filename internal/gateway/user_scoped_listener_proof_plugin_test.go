// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// renderListenerProofPlugin fills the plugin template's placeholders the way
// the Windows standalone guardian does: loopback TCP, the per-user
// credential file, closed fail mode, and the listener proof on.
func renderListenerProofPlugin(t *testing.T, asset, addr, tokenPath string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("connector", "hooks", asset))
	if err != nil {
		t.Fatal(err)
	}
	quotedPath := strconv.Quote(tokenPath)
	rendered := strings.NewReplacer(
		"{{.APIAddr}}", addr,
		"{{.TokenFileJS}}", quotedPath[1:len(quotedPath)-1],
		"{{.FailMode}}", "closed",
		"{{.HookSocketJS}}", "",
		"{{.ServiceUID}}", "0",
		"{{.ForeignHookGuardJS}}", "",
		"{{.InstallMarkerJS}}", "",
		"{{.ListenerProofJS}}", "1",
	).Replace(string(body))
	if strings.Contains(rendered, "{{.") {
		t.Fatalf("%s rendered with a placeholder left", asset)
	}
	return []byte(rendered)
}

const openCodeGatewayProofHarness = `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.DefenseClaw({ directory: "" });
try {
  await plugin["tool.execute.before"](
    { tool: "Bash", sessionID: "S", messageID: "M", callID: "C" },
    { args: { command: "printf listener-proof-marker" } },
  );
  console.log("allow");
} catch (error) {
  console.log("block:" + String(error && error.message || error));
}
`

const ampGatewayProofHarness = `
import { pathToFileURL } from "node:url";
import { readFile } from "node:fs/promises";
globalThis.Bun = {
  file: (path) => ({ slice: (start, end) => ({ text: async () => (await readFile(path, "utf8")).slice(start, end) }) }),
};
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
const result = await handlers["tool.call"](
  { thread: { id: "T" }, toolUseID: "U", tool: "Bash", input: { command: "printf listener-proof-marker" } },
  { thread: { agent: async () => { throw new Error("no agent"); } }, ui: { confirm: async () => false } },
);
console.log(result && result.action === "allow" ? "allow" : "block:" + String(result && result.message));
`

// The in-agent plugins and the gateway agree on the listener proof: each
// plugin, rendered as the Windows standalone guardian renders it, proves the
// real gateway authentication chain, then sends its per-user credential and
// the event, which the gateway attributes to the credential's user. The
// plugin sends the same identity headers it sends in production, so the
// credential is bound to this test process's own account.
func TestInAgentPluginsProveTheGatewayListener(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the plugin listener proof test")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the plugins report a POSIX uid here; Windows binds a SID (connector package covers the plugin side there)")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid := current.Uid
	for _, tc := range []struct {
		asset, connectorName, hookPath, harness, file, allow string
	}{
		{"opencode-plugin.js", "opencode", "/api/v1/opencode/hook", openCodeGatewayProofHarness, "opencode-plugin.mjs", `{"hook_output":{"decision":"allow"}}`},
		{"amp-plugin.ts", "amp", "/api/v1/amp/hook", ampGatewayProofHarness, "amp-plugin.mts", `{"action":"allow"}`},
	} {
		t.Run(tc.connectorName, func(t *testing.T) {
			ledger := &userScopedTestLedger{}
			ledger.set(managedHookLedgerTarget{User: current.Username, UID: userScopedTestUID(mustAtoi(t, uid)), Connector: tc.connectorName, OK: true})
			api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{uid: current.Username})
			var (
				mu     sync.Mutex
				served []string
			)
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				served = append(served, r.URL.Path+" user="+r.Header.Get(llmEventUserIDHeader)+" connector="+authenticatedHookConnector(r.Context())+" marker="+strconv.FormatBool(strings.Contains(string(body), "listener-proof-marker")))
				mu.Unlock()
				_, _ = io.WriteString(w, tc.allow)
			})
			server := httptest.NewServer(CorrelationMiddleware(NewAgentRegistry("", ""))(api.tokenAuth(next)))
			t.Cleanup(server.Close)

			credential := userScopedTestToken(t, connector.UserScopedHookCredential, tc.connectorName, uid)
			dir := t.TempDir()
			tokenPath := filepath.Join(dir, ".hook-"+tc.connectorName+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			plugin := filepath.Join(dir, tc.file)
			if err := os.WriteFile(plugin, renderListenerProofPlugin(t, tc.asset, strings.TrimPrefix(server.URL, "http://"), tokenPath), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", tc.harness, plugin)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("node: %v; stderr=%s", err, stderr.String())
			}
			mu.Lock()
			defer mu.Unlock()
			want := tc.hookPath + " user=" + uid + " connector=" + tc.connectorName + " marker=true"
			if verdict := strings.TrimSpace(string(out)); verdict != "allow" || len(served) != 1 || served[0] != want {
				t.Fatalf("verdict %q, served %q; want allow and %q", verdict, served, want)
			}
		})
	}
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	n, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
