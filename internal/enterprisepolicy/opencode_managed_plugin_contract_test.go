// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// openCodeFakeHook stands in for <InstallRoot>/bin/defenseclaw-hook: it logs
// its argv and stdin and answers from a file the harness writes.
const openCodeFakeHook = `#!/usr/bin/env node
const fs = require("node:fs");
const dir = process.env.DC_FAKE_DIR;
let stdin = "";
process.stdin.on("data", (chunk) => { stdin += chunk; });
process.stdin.on("end", () => {
  const args = process.argv.slice(2);
  fs.appendFileSync(dir + "/calls.jsonl", JSON.stringify({ args, stdin }) + "\n");
  const file = args.includes("--foreign-hook-check") ? "guard.json" : "event.json";
  const { stdout, exit } = JSON.parse(fs.readFileSync(dir + "/" + file, "utf8"));
  if (stdout) process.stdout.write(stdout + "\n");
  process.exit(exit);
});
`

// TestOpenCodeManagedPluginContract loads the shipped managed plugin in node
// from a payload-shaped tree and drives it against a fake hook binary.
func TestOpenCodeManagedPluginContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake hook binary is a script")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	// Node reports the plugin by its resolved path, and on macOS the
	// temporary folder is under the /var symlink; name it the same way.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(root, "share", "opencode", "defenseclaw.js")
	writeFile(t, plugin, string(OpenCodeManagedPlugin()))
	// OpenCode loads the plugin as an ES module; tell node the same.
	writeFile(t, filepath.Join(root, "share", "opencode", "package.json"), `{"type":"module"}`)
	hook := filepath.Join(root, "bin", "defenseclaw-hook")
	writeFile(t, hook, openCodeFakeHook)
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := t.TempDir()
	cmd := exec.Command(node, filepath.Join("testdata", "opencode-managed-plugin-contract.mjs"), plugin, fake)
	cmd.Env = append(os.Environ(), "DC_FAKE_DIR="+fake)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("managed OpenCode plugin contract failed: %v\n%s", err, out)
	}
}
