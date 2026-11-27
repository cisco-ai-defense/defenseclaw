// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0636: with the folder facts, the kit reports the programs the
// packages in the actor's npx cache declare (default cache and the one
// npm_config_cache names), so the gateway does not have to guess them. The
// role is spelled out so the test builds at a parent without the constant.
func TestGAP0636KitReportsNpxCacheBins(t *testing.T) {
	const role = "mcp_fetch_bins"
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("NPM_CONFIG_CACHE", "")
	other := t.TempDir()
	t.Setenv("npm_config_cache", other)
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	npx := filepath.Join(home, ".npm", "_npx")
	write(filepath.Join(npx, "a1", "package.json"), `{"dependencies":{"@acme/tools":"^1.4.0"}}`)
	write(filepath.Join(npx, "a1", "node_modules", "@acme", "tools", "package.json"), `{"name":"@acme/tools","bin":{"acme-run":"r.js","sub/acme-two":"t.js"}}`)
	write(filepath.Join(npx, "b2", "package.json"), `{"dependencies":{"strbin":"1.0.0","dirpkg":"1.0.0","nobin":"1"}}`)
	write(filepath.Join(npx, "b2", "node_modules", "strbin", "package.json"), `{"bin":"cli.js"}`)
	write(filepath.Join(npx, "b2", "node_modules", "dirpkg", "package.json"), `{"directories":{"bin":"./bin"}}`)
	write(filepath.Join(npx, "b2", "node_modules", "dirpkg", "bin", "dp-one"), "")
	write(filepath.Join(npx, "b2", "node_modules", "nobin", "package.json"), `{"name":"nobin"}`)
	// A dependency name that is a path is not followed out of node_modules.
	write(filepath.Join(npx, "c3", "package.json"), `{"dependencies":{"../../c3x":"1"}}`)
	write(filepath.Join(npx, "c3x", "package.json"), `{"bin":{"outside":"o.js"}}`)
	write(filepath.Join(other, "_npx", "d4", "package.json"), `{"dependencies":{"envpkg":"2"}}`)
	write(filepath.Join(other, "_npx", "d4", "node_modules", "envpkg", "package.json"), `{"bin":{"env-run":"e.js"}}`)

	repo := filepath.Join(home, "work", "repo")
	write(filepath.Join(repo, ".mcp.json"), `{"mcpServers":{"t":{"command":"npx","args":["-y","@acme/tools"]}}}`)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "mcp__t__run", "tool_input": map[string]any{}})
	f := CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes)
	if f == nil {
		t.Fatal("no facts")
	}
	got := map[string]string{}
	for _, a := range f.Files {
		if a.Role == role {
			if a.Truncated {
				t.Errorf("%s: cut", a.Path)
			}
			got[a.Path] = string(a.Content)
		}
	}
	want := map[string]string{
		npx:                          strings.Join([]string{"@acme/tools\tacme-run", "@acme/tools\tacme-two", "dirpkg\tdp-one", "strbin\tstrbin"}, "\n"),
		filepath.Join(other, "_npx"): "envpkg\tenv-run",
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: %q, want %q", p, got[p], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("cache lists %v, want %d", got, len(want))
	}
}
