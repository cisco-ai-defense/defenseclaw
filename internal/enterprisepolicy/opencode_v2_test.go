// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestOpenCodeV2ManagedPluginContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake hook is a script")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(root, "share", "opencode", "index.js")
	writeFile(t, plugin, string(OpenCodeManagedPlugin()))
	writeFile(t, filepath.Join(root, "share", "opencode", "package.json"), `{"type":"module"}`)
	hook := filepath.Join(root, "bin", "defenseclaw-hook")
	writeFile(t, hook, openCodeFakeHook)
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := t.TempDir()
	shared, err := filepath.Abs("../opencodebridge/testdata/contract.mjs")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "--input-type=module", "-e", `
import {pathToFileURL} from "node:url";
import {readFileSync, writeFileSync} from "node:fs";
const [path, shared, fake] = process.argv.slice(1);
writeFileSync(fake + "/guard.json", JSON.stringify({stdout:'{"deny":false}',exit:0}));
const {default: plugin} = await import(pathToFileURL(path));
const {contract} = await import(pathToFileURL(shared));
await contract(plugin, {
  reply: async (value) => writeFileSync(fake + "/event.json", JSON.stringify({stdout:JSON.stringify(value),exit:0})),
  payloads: async () => readFileSync(fake + "/calls.jsonl", "utf8").trim().split("\n")
    .map((line) => JSON.parse(line)).filter((call) => call.args.includes("--enterprise-managed"))
    .map((call) => JSON.parse(call.stdin)),
});`, plugin, shared, fake)
	cmd.Env = append(os.Environ(), "DC_FAKE_DIR="+fake)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("v2 managed contract: %v\n%s", err, output)
	}
}

func TestOpenCodeV2ForeignPluginsAreGuardedAndRemoved(t *testing.T) {
	req := guardRequest(t, "opencode", config.ForeignHooksRemove)
	path := filepath.Join(req.Home, ".config", "opencode", "opencode.json")
	writeFile(t, path, `{"plugins":["foreign-package",{"package":"another-package","options":{"audit":true}}],"mcp":{"servers":{}}}`)
	if decision := EvaluateForeignHooks(req); !decision.Deny || len(decision.Findings) != 2 {
		t.Fatalf("guard missed v2 entries: %+v", decision)
	}
	if _, err := CleanUserForeignHooks(req, time.Now()); err != nil {
		t.Fatal(err)
	}
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("cleanup left foreign plugins: %+v", decision)
	}
	if body := readFile(t, path); !strings.Contains(body, `"servers"`) {
		t.Fatalf("cleanup changed MCP settings: %s", body)
	}
}

func TestOpenCodeV2ManagedConfigUpgrade(t *testing.T) {
	opts := Options{GOOS: "linux", OpenCodePluginPath: testOpenCodePlugin}
	legacy := strings.Replace(testOpenCodePlugin, "index.js", "defenseclaw.js", 1)
	for _, initial := range []string{
		`{"plugin":["company", "` + legacy + `"]}`,
		`{"plugins":[{"package":"company","options":{"audit":true}},"file://` + legacy + `"],"mcp":{"servers":{}}}`,
	} {
		merged, _, err := mergeOpenCodeConfig(opts, []byte(initial))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(merged), "defenseclaw.js") || !strings.Contains(string(merged), openCodePluginSpec(opts)) {
			t.Fatalf("not migrated to a directory: %s", merged)
		}
		if _, exact, err := mergeOpenCodeConfig(opts, merged); err != nil || !exact {
			t.Fatalf("not idempotent: %v, %v", exact, err)
		}
		stripped, changed, err := stripOpenCodeConfig(opts, merged)
		if err != nil || !changed || strings.Contains(string(stripped), openCodePluginSpec(opts)) || !strings.Contains(string(stripped), "company") {
			t.Fatalf("removal did not preserve operator settings: %s, %v", stripped, err)
		}
	}
}

// GAP-0072: a downgrade to 1.0.5 leaves the 1.0.6 folder entry in the managed
// config next to 1.0.5's own defenseclaw.js entry (1.0.5 does not know the
// folder entry). The next 1.0.6 ensure or repair owns both and rewrites the
// file to the single folder entry; the operator's entries stay.
func TestOpenCodeManagedConfigAfterADowngradeIsReconciled(t *testing.T) {
	opts := Options{GOOS: "linux", OpenCodePluginPath: testOpenCodePlugin}
	folder := openCodePluginSpec(opts)
	legacy := strings.Replace(testOpenCodePlugin, "index.js", "defenseclaw.js", 1)
	residue := `{"plugin":["company","` + folder + `","` + legacy + `"],"mcp":{"servers":{}}}`

	merged, exact, err := mergeOpenCodeConfig(opts, []byte(residue))
	if err != nil || exact {
		t.Fatalf("the residue must be rewritten: exact=%v err=%v", exact, err)
	}
	if strings.Count(string(merged), folder) != 1 || strings.Contains(string(merged), "defenseclaw.js") ||
		!strings.Contains(string(merged), "company") || !strings.Contains(string(merged), `"servers"`) {
		t.Fatalf("not reconciled to the single folder entry: %s", merged)
	}
	stripped, changed, err := stripOpenCodeConfig(opts, []byte(residue))
	if err != nil || !changed || strings.Contains(string(stripped), "defenseclaw.js") || strings.Contains(string(stripped), folder) ||
		!strings.Contains(string(stripped), "company") {
		t.Fatalf("removal left a DefenseClaw entry or lost the operator's: %s, %v", stripped, err)
	}
}
