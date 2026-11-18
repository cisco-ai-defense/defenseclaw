// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// GAP-0573: the GAP-0551 fetcher branch took any first operand that looked
// like a package name as "runs nothing of the folder", so npx running the
// project's own program (package.json bin, node_modules/.bin), a project
// .npmrc, npm_config_* or UV_* env, npx -c, --package=./x, pipx run
// --spec ., uvx --python=./x, --with=./x, --find-links and a fetched
// runner given code (tsx -e, python -c) were allowed in strict mode. Each
// is now unscanned (strict refuses, OSS allows with an alert), from the
// kit's folder facts through the gateway. The registry servers people
// really run in a clean folder stay allowed in strict, and so do three
// servers strict refused before (GAP-0575): an installed program given the
// project as data, a container image with no mount, and a bare installed
// name the kit finds outside the folder.
func TestGAP0573FetcherFolderShapesFollowTheFailMode(t *testing.T) {
	src := "import json, sys\nfor line in sys.stdin:\n    print(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'tools': []}}))\n"
	js := "#!/usr/bin/env node\nprocess.stdin.on('data',()=>{})\n"
	sh := "#!/bin/sh\nexec python3 \"$(dirname \"$0\")/../../tools/evil_server.py\"\n"
	srv := func(s string) string { return `{"mcpServers":{"evil":` + s + `}}` }
	py := map[string]string{"tools/evil_server.py": src}
	clean := map[string]string{"x.txt": "x\n"}
	type tc struct {
		cfg    string
		files  map[string]string
		benign bool
	}
	cases := map[string]tc{
		"E01 npx unpinned + node_modules/.bin/<name>":    {srv(`{"command":"npx","args":["-y","mcp-server-everything"]}`), map[string]string{"node_modules/.bin/mcp-server-everything": sh, "tools/evil_server.py": src}, false},
		"E02 npx pinned + node_modules/.bin/<name@ver>":  {srv(`{"command":"npx","args":["-y","mcp-server-everything@1.0.0"]}`), map[string]string{"node_modules/.bin/mcp-server-everything@1.0.0": sh, "tools/evil_server.py": src}, false},
		"E03 npx pinned + project .npmrc node-options":   {srv(`{"command":"npx","args":["-y","@modelcontextprotocol/server-everything@2025.1.14"]}`), map[string]string{".npmrc": "node-options=--require ./tools/evil.js\n", "tools/evil.js": js}, false},
		"E04 npx pinned + env npm_config_node_options":   {srv(`{"command":"npx","args":["-y","@modelcontextprotocol/server-everything@2025.1.14"],"env":{"npm_config_node_options":"--require ./tools/evil.js"}}`), map[string]string{"tools/evil.js": js}, false},
		"E05 npx -y -c inline":                           {srv(`{"command":"npx","args":["-y","-c","python3 tools/evil_server.py"]}`), py, false},
		"E06 npx --package=./tools/pkg bin":              {srv(`{"command":"npx","args":["-y","--package=./tools/pkg","evilbin"]}`), map[string]string{"tools/pkg/package.json": `{"name":"e","version":"1.0.0","bin":{"evilbin":"evil.js"}}`, "tools/pkg/evil.js": js}, false},
		"E07 npx unpinned + package.json bin":            {srv(`{"command":"npx","args":["-y","mcp-server-everything"]}`), map[string]string{"package.json": `{"name":"p","version":"1.0.0","bin":{"mcp-server-everything":"tools/evil.js"}}`, "tools/evil.js": js}, false},
		"E08 pipx run --spec . pkg":                      {srv(`{"command":"pipx","args":["run","--spec",".","evilpy"]}`), map[string]string{"pyproject.toml": "[project]\nname='evilpy'\n", "evilpy/__init__.py": src}, false},
		"E09 uvx --python=./tools/py pkg":                {srv(`{"command":"uvx","args":["--python=./tools/py","mcp-server-fetch==2025.4.7"]}`), map[string]string{"tools/py": "#!/bin/sh\nexec python3 tools/evil_server.py\n", "tools/evil_server.py": src}, false},
		"E10 uvx --with=./tools/pkg pkg":                 {srv(`{"command":"uvx","args":["--with=./tools/pkg","mcp-server-fetch==2025.4.7"]}`), map[string]string{"tools/pkg/pyproject.toml": "[project]\nname='x'\n", "tools/pkg/x/__init__.py": src}, false},
		"E11 uvx --find-links=./wheels pkg":              {srv(`{"command":"uvx","args":["--find-links=./wheels","mcp-server-fetch"]}`), map[string]string{"wheels/README": "x\n"}, false},
		"E12 uvx + env UV_FIND_LINKS=./wheels":           {srv(`{"command":"uvx","args":["mcp-server-fetch"],"env":{"UV_FIND_LINKS":"./wheels"}}`), map[string]string{"wheels/README": "x\n"}, false},
		"E13 npx -y tsx -e require":                      {srv(`{"command":"npx","args":["-y","tsx@4.19.2","-e","require('./tools/evil.js')"]}`), map[string]string{"tools/evil.js": js}, false},
		"E14 uvx python -c import":                       {srv(`{"command":"uvx","args":["python","-c","import tools.evil_server"]}`), map[string]string{"tools/evil_server.py": src, "tools/__init__.py": ""}, false},
		"E15 docker run -v the project":                  {srv(`{"command":"docker","args":["run","-i","--rm","-v","@REPO@:/w","node:20","node","/w/tools/evil.js"]}`), map[string]string{"tools/evil.js": js}, false},
		"E16 docker run --entrypoint":                    {srv(`{"command":"docker","args":["run","-i","--rm","--entrypoint=/bin/sh","alpine","-c","id"]}`), clean, false},
		"E17 bare name found in the folder":              {srv(`{"command":"gap0573-local-srv"}`), map[string]string{"bin/gap0573-local-srv": sh, "tools/evil_server.py": src}, false},
		"E18 uvx --from=./ pkg":                          {srv(`{"command":"uvx","args":["--from=./","evil-server"]}`), py, false},
		"E19 npx with an unknown option":                 {srv(`{"command":"npx","args":["-y","--node-options=--require=./tools/evil.js","mcp-server-everything@1.0.0"]}`), map[string]string{"tools/evil.js": js}, false},
		"E20 npx unpinned + project .npmrc node-options": {srv(`{"command":"npx","args":["-y","@modelcontextprotocol/server-everything"]}`), map[string]string{".npmrc": "node-options=--require ./tools/evil.js\n", "tools/evil.js": js}, false},
		"E21 npx pinned + package.json bin same name":    {srv(`{"command":"npx","args":["-y","mcp-server-everything@1.0.0"]}`), map[string]string{"package.json": `{"name":"p","version":"1.0.0","bin":{"mcp-server-everything":"tools/evil.js"}}`, "tools/evil.js": js}, false},
		"E22 npx pinned + node_modules/.bin/<name>":      {srv(`{"command":"npx","args":["-y","mcp-server-everything@1.0.0"]}`), map[string]string{"node_modules/.bin/mcp-server-everything": sh, "tools/evil_server.py": src}, false},
		"E23 npx pinned + package.json bin, parent dir":  {srv(`{"command":"npx","args":["-y","mcp-server-everything@1.0.0"]}`), map[string]string{"../package.json": `{"name":"mono","bin":{"mcp-server-everything":"evil.js"}}`}, false},
		"F01 uvx mcp-server-git (unpinned)":              {srv(`{"command":"uvx","args":["mcp-server-git","--repository","."]}`), clean, true},
		"F02 npx pinned server-filesystem /tmp":          {srv(`{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2025.8.21","/tmp"]}`), clean, true},
		"F03 npx unpinned server-filesystem /tmp":        {srv(`{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}`), clean, true},
		"F04 installed program, project as data":         {srv(`{"command":"/usr/local/bin/mcp-server-filesystem","args":["@REPO@"]}`), clean, true},
		"F05 docker run github-mcp-server (no mount)":    {srv(`{"command":"docker","args":["run","-i","--rm","-e","GITHUB_PERSONAL_ACCESS_TOKEN","ghcr.io/github/github-mcp-server"]}`), clean, true},
		"F06 bare installed name mcp-server-git":         {srv(`{"command":"gap0573-installed-srv","args":["--repository","."]}`), clean, true},
		"F09 uvx pinned mcp-server-fetch":                {srv(`{"command":"uvx","args":["mcp-server-fetch==2025.4.7"]}`), clean, true},
		"F10 npx unpinned server-everything":             {srv(`{"command":"npx","args":["-y","@modelcontextprotocol/server-everything"]}`), clean, true},
		"F11 npx in a project with a plain package.json": {srv(`{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","."]}`), map[string]string{"package.json": `{"name":"app","version":"1.0.0","scripts":{"test":"x"}}`}, true},
		"F12 uvx in a Python project":                    {srv(`{"command":"uvx","args":["mcp-server-git"]}`), map[string]string{"pyproject.toml": "[project]\nname='app'\n"}, true},
	}
	// An installed program outside the folder, and the folder's own bin on
	// the actor's PATH (E17: the kit resolves it into the folder).
	installed := t.TempDir()
	if err := os.WriteFile(filepath.Join(installed, "gap0573-installed-srv"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		c := cases[name]
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			repo := t.TempDir()
			t.Setenv("PATH", installed+string(os.PathListSeparator)+filepath.Join(repo, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			files := map[string]string{".mcp.json": strings.ReplaceAll(c.cfg, "@REPO@", repo)}
			for k, v := range c.files {
				files[k] = v
			}
			for n, body := range files {
				p := filepath.Join(repo, filepath.FromSlash(n))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			wd, _ := os.Getwd()
			if err := os.Chdir(repo); err != nil { // the kit runs in the project, as the hook does
				t.Fatal(err)
			}
			defer os.Chdir(wd)
			call := func() map[string]any {
				return map[string]any{"cwd": repo, "tool_name": "mcp__evil__add_numbers", "tool_input": map[string]any{"a": 1, "b": 2}}
			}
			rs := gap0185Kit(t, true, "PreToolUse", call())
			ro := gap0185Kit(t, false, "PreToolUse", call())
			oAlert := strings.TrimSpace(strings.Join(ro.alerts, " | "))
			if ro.refused() {
				t.Fatalf("OSS refused (code %d): %s", ro.code, ro.out)
			}
			if c.benign {
				if rs.refused() {
					t.Errorf("strict refused a server that runs nothing of the folder (code %d): %s", rs.code, rs.out)
				}
				return
			}
			if !rs.refused() {
				t.Errorf("strict allowed a server that runs folder code (code %d, OSS alerts %q)", rs.code, oAlert)
			}
			if oAlert == "" {
				t.Errorf("OSS allowed with no alert")
			}
		})
	}
}
