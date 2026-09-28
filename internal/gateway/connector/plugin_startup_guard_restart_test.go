// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// flakyForeignGuard is a stand-in for the administrator-owned hook binary
// whose foreign-hook check cannot run the first time (for example while an
// upgrade replaces it) and answers allow afterwards.
const flakyForeignGuard = `#!/bin/sh
cat >/dev/null
if [ ! -f "$0.ran" ]; then
  : > "$0.ran"
  echo "hook binary unavailable" >&2
  exit 1
fi
printf '{"deny":false}\n'
`

func writeFlakyForeignGuard(t *testing.T, root string) string {
	t.Helper()
	guard := filepath.Join(root, "defenseclaw-hook")
	if err := os.WriteFile(guard, []byte(flakyForeignGuard), 0o700); err != nil {
		t.Fatal(err)
	}
	return guard
}

// OpenCode and Amp load plugins once, so the foreign-plugin check at load
// is kept for the life of the process: a plugin loaded then keeps running
// even if its file is removed later. When that check itself fails, every
// later tool call stays blocked even once the check would succeed, so the
// reason says to restart the agent; a restarted agent checks again.
func TestPluginStartupGuardFailureSaysToRestart(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	data := openCodePluginTestData(t, openCodeStubGateway(t))
	data.ForeignHookGuardJS = javaScriptStringContent(writeFlakyForeignGuard(t, root))
	data.Managed = true
	lines := runNodeHarness(t, `
import { pathToFileURL } from "node:url";
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const call = async (plugin, id) => {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: id }, { args: { command: "echo marker" } });
    return "allow";
  } catch (error) {
    return "block:" + String(error && error.message || error);
  }
};
const first = await loaded.DefenseClaw({ directory: "", client: {} });
await first.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(first, "C1"));
console.log(await call(first, "C2"));
const restarted = await loaded.DefenseClaw({ directory: "", client: {} });
await restarted.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(restarted, "C3"));
`, writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", data))
	if len(lines) != 3 || lines[2] != "allow" {
		t.Fatalf("OpenCode verdicts = %q, want two blocks and an allow after the restart", lines)
	}
	for _, line := range lines[:2] {
		if !strings.HasPrefix(line, "block:") || !strings.Contains(line, "Restart the agent") {
			t.Fatalf("OpenCode: a failed load-time check must keep blocking and say to restart: %q", line)
		}
	}

	ampRoot := testenv.PrivateTempDir(t)
	lines = runNodeHarness(t, `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
for (const id of ["U1", "U2"]) {
  const result = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: id, tool: "Bash", input: {} }, {});
  console.log(result.action + ":" + (result.message || ""));
}
`, writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", templateData{
		APIAddr:            "127.0.0.1:18970",
		TokenFileJS:        javaScriptStringContent(filepath.Join(ampRoot, ".hook-amp.token")),
		ForeignHookGuardJS: javaScriptStringContent(writeFlakyForeignGuard(t, ampRoot)),
		FailMode:           "closed",
		Managed:            true,
	}))
	if len(lines) != 2 {
		t.Fatalf("Amp verdicts = %q", lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "reject-and-continue:") || !strings.Contains(line, "Restart the agent") {
			t.Fatalf("Amp: a failed load-time check must keep blocking and say to restart: %q", line)
		}
	}
	if _, err := os.Stat(filepath.Join(ampRoot, "defenseclaw-hook.ran")); err != nil {
		t.Fatalf("the guard did not run at load: %v", err)
	}
}
