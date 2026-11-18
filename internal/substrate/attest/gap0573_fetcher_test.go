// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import "testing"

// GAP-0573: a registry fetcher is known to run nothing of the folder only
// when every option is read with its value, the package is the registry's
// and the kit looked at the folder and found nothing the fetcher resolves
// there. Unit rows for the folder facts the kit reports.
func TestGAP0573FetcherNeedsTheKitFolderFacts(t *testing.T) {
	checked := AttachedFile{Role: RoleFetchChecked, Path: "/work/repo"}
	local := func(p string) AttachedFile { return AttachedFile{Role: RoleFetchLocal, Path: "/work/repo/" + p} }
	pj := func(s string) AttachedFile {
		return AttachedFile{Role: RoleFetchConfig, Path: "/work/repo/package.json", Content: []byte(s)}
	}
	names := func(s string) AttachedFile {
		return AttachedFile{Role: RoleFetchNames, Path: "/work/repo/node_modules", Content: []byte(s)}
	}
	npx := []string{"-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"}
	uvx := []string{"mcp-server-git"}
	type row struct {
		cmd   string
		args  []string
		env   map[string]string
		files []AttachedFile
	}
	unknown := map[string]row{
		"no kit record (older kit)":        {"npx", npx, nil, nil},
		"kit record for another folder":    {"npx", npx, nil, []AttachedFile{{Role: RoleFetchChecked, Path: "/work/other"}}},
		".npmrc in the folder":             {"npx", npx, nil, []AttachedFile{checked, local(".npmrc")}},
		"bunfig.toml for bunx":             {"bunx", []string{"some-mcp"}, nil, []AttachedFile{checked, local("bunfig.toml")}},
		"pip.conf for uvx":                 {"uvx", uvx, nil, []AttachedFile{checked, local("pip.conf")}},
		"uv.toml for uvx":                  {"uvx", uvx, nil, []AttachedFile{checked, local("uv.toml")}},
		"unreadable package.json":          {"npx", npx, nil, []AttachedFile{checked, local("package.json")}},
		"package.json bin":                 {"npx", npx, nil, []AttachedFile{checked, pj(`{"name":"p","bin":{"x":"x.js"}}`)}},
		"package.json bin string":          {"npx", npx, nil, []AttachedFile{checked, pj(`{"name":"p","bin":"x.js"}`)}},
		"package.json workspaces":          {"npx", npx, nil, []AttachedFile{checked, pj(`{"name":"p","workspaces":["pkgs/*"]}`)}},
		"package.json is the package":      {"npx", npx, nil, []AttachedFile{checked, pj(`{"name":"@modelcontextprotocol/server-filesystem"}`)}},
		"package.json cut":                 {"npx", npx, nil, []AttachedFile{checked, {Role: RoleFetchConfig, Path: "/work/repo/package.json", Truncated: true}}},
		"the package's program in .bin":    {"npx", npx, nil, []AttachedFile{checked, names("left-pad\n.bin/mcp-server-filesystem")}},
		"the program as a Windows shim":    {"npx", npx, nil, []AttachedFile{checked, names(".bin/MCP-Server-Filesystem.cmd")}},
		"node in .bin (the runtime)":       {"npx", npx, nil, []AttachedFile{checked, names("left-pad\n.bin/node")}},
		"the --package program in .bin":    {"npx", []string{"-y", "--package=@playwright/mcp@0.0.30", "mcp-server-playwright"}, nil, []AttachedFile{checked, names(".bin/mcp-server-playwright")}},
		"the package in node_modules":      {"npx", npx, nil, []AttachedFile{checked, names("@modelcontextprotocol/server-filesystem")}},
		"node_modules list cut":            {"npx", npx, nil, []AttachedFile{checked, {Role: RoleFetchNames, Path: "/work/repo/node_modules", Truncated: true}}},
		"npm_config_ env, any case":        {"npx", npx, map[string]string{"NPM_CONFIG_NODE_OPTIONS": "--require ./x.js"}, []AttachedFile{checked}},
		"UV_ env":                          {"uvx", uvx, map[string]string{"UV_INDEX_URL": "file:///work/repo/idx"}, []AttachedFile{checked}},
		"PIP_ env for pipx":                {"pipx", []string{"run", "mcp-server-git"}, map[string]string{"PIP_FIND_LINKS": "./w"}, []AttachedFile{checked}},
		"npx -c":                           {"npx", []string{"-c", "node x.js"}, nil, []AttachedFile{checked}},
		"npx --call=":                      {"npx", []string{"--call=node x.js"}, nil, []AttachedFile{checked}},
		"npx -p ./pkg":                     {"npx", []string{"-p", "./pkg", "bin"}, nil, []AttachedFile{checked}},
		"npx file: spec":                   {"npx", []string{"-y", "file:./pkg"}, nil, []AttachedFile{checked}},
		"npx github shorthand":             {"npx", []string{"-y", "tools/pkg"}, nil, []AttachedFile{checked}},
		"npx --package=x ./bin":            {"npx", []string{"--package=some-mcp", "./bin/x"}, nil, []AttachedFile{checked}},
		"npx --package=tsx tsx":            {"npx", []string{"--package=tsx", "tsx", "-e", "1"}, nil, []AttachedFile{checked}},
		"npx no package":                   {"npx", []string{"-y"}, nil, []AttachedFile{checked}},
		"npx flag given a value":           {"npx", []string{"--yes=true", "some-mcp"}, nil, []AttachedFile{checked}},
		"npx fetched node":                 {"npx", []string{"-y", "node@20", "x.js"}, nil, []AttachedFile{checked}},
		"uvx --from .":                     {"uvx", []string{"--from", ".", "x"}, nil, []AttachedFile{checked}},
		"uvx --with-editable":              {"uvx", []string{"--with-editable", "pkg", "x"}, nil, []AttachedFile{checked}},
		"uvx --with a,./b":                 {"uvx", []string{"--with", "requests,./b", "x"}, nil, []AttachedFile{checked}},
		"uvx -p ./py":                      {"uvx", []string{"-p", "./py", "x"}, nil, []AttachedFile{checked}},
		"uvx --index-url":                  {"uvx", []string{"--index-url", "file:///work/repo/i", "x"}, nil, []AttachedFile{checked}},
		"uvx --directory":                  {"uvx", []string{"--directory", ".", "x"}, nil, []AttachedFile{checked}},
		"uvx a wheel":                      {"uvx", []string{"./dist/x-1.0-py3-none-any.whl"}, nil, []AttachedFile{checked}},
		"uvx --from x python":              {"uvx", []string{"--from", "x", "python", "-c", "1"}, nil, []AttachedFile{checked}},
		"uvx python3.12":                   {"uvx", []string{"python3.12", "-c", "1"}, nil, []AttachedFile{checked}},
		"pipx not run":                     {"pipx", []string{"install", "x"}, nil, []AttachedFile{checked}},
		"pipx run --spec .":                {"pipx", []string{"run", "--spec", ".", "x"}, nil, []AttachedFile{checked}},
		"pipx run --pip-args":              {"pipx", []string{"run", "--pip-args=--find-links=./w", "x"}, nil, []AttachedFile{checked}},
		"fetcher program of the folder":    {"/work/repo/node_modules/.bin/npx", npx, nil, []AttachedFile{checked}},
		"relative venv python":             {"./.venv/bin/python", []string{"-m", "mcp_server_time"}, nil, []AttachedFile{{Role: RoleMCPModuleAbsent, Path: "mcp_server_time"}}},
		"relative fetcher":                 {"node_modules/.bin/npx", npx, nil, []AttachedFile{checked}},
		"bare fetcher resolved in folder":  {"npx", npx, nil, []AttachedFile{checked, {Role: RoleCommandPath, Path: "npx", Content: []byte("/work/repo/.bin/npx")}}},
		"docker -v":                        {"docker", []string{"run", "-i", "-v", "/work/repo:/w", "img"}, nil, nil},
		"docker --mount":                   {"docker", []string{"run", "--mount", "type=bind,src=.,dst=/w", "img"}, nil, nil},
		"docker -w":                        {"docker", []string{"run", "-w", "/w", "img"}, nil, nil},
		"docker --env-file":                {"docker", []string{"run", "--env-file", ".env", "img"}, nil, nil},
		"docker --entrypoint":              {"docker", []string{"run", "--entrypoint", "sh", "img"}, nil, nil},
		"docker --privileged":              {"docker", []string{"run", "--privileged", "img"}, nil, nil},
		"docker not run":                   {"docker", []string{"compose", "up"}, nil, nil},
		"docker local image path":          {"docker", []string{"run", "./img"}, nil, nil},
		"DOCKER_CONFIG env":                {"docker", []string{"run", "-i", "img"}, map[string]string{"DOCKER_CONFIG": "./d"}, nil},
		"bare name not resolved (old kit)": {"mcp-server-git", nil, nil, nil},
		"bare name resolved in the folder": {"srv", nil, nil, []AttachedFile{{Role: RoleCommandPath, Path: "srv", Content: []byte("/work/repo/bin/srv")}}},
		"bare python resolved in a venv":   {"python3", []string{"-m", "mcp_server_time"}, nil, []AttachedFile{{Role: RoleCommandPath, Path: "python3", Content: []byte("/work/repo/.venv/bin/python3")}, {Role: RoleMCPModuleAbsent, Path: "mcp_server_time"}}},
		"wrapper runs a folder program":    {"/usr/bin/timeout", []string{"60", "sh", "-c", "python3 tools/x"}, nil, nil},
		"installed git with repo config":   {"/usr/bin/git", []string{"-C", ".", "evil"}, nil, nil},
		"LD_ env":                          {"/usr/local/bin/srv", nil, map[string]string{"LD_AUDIT": "./x.so"}, nil},
		"lower-case code-loading env":      {"/usr/local/bin/srv", nil, map[string]string{"node_options": "--require ./x.js"}, nil},
	}
	for name, r := range unknown {
		if d := repoServerDecision(t, r.cmd, r.args, r.env, r.files...); !d.Unavailable {
			t.Errorf("%s: %+v, want unscanned (the fail mode decides)", name, d)
		}
	}
	known := map[string]row{
		"npx pinned, clean folder":              {"npx", npx, nil, []AttachedFile{checked}},
		"npx unpinned, clean folder":            {"npx", []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, nil, []AttachedFile{checked}},
		"npx, a plain package.json":             {"npx", npx, nil, []AttachedFile{checked, pj(`{"name":"app","scripts":{"t":"x"},"bin":{}}`)}},
		"npx, node_modules without programs":    {"npx", npx, nil, []AttachedFile{checked, names("left-pad")}},
		"npx, the project's own tools in .bin":  {"npx", npx, nil, []AttachedFile{checked, names("typescript\neslint\n.bin/tsc\n.bin/eslint\n.bin/node-gyp\n.bin/tsc.cmd")}},
		"npx, pip.conf is not npm's":            {"npx", npx, nil, []AttachedFile{checked, local("pip.conf")}},
		"npx --package=x bin":                   {"npx", []string{"-y", "--package=@playwright/mcp@0.0.30", "mcp-server-playwright"}, nil, []AttachedFile{checked}},
		"npx -- spec":                           {"npx", []string{"-y", "--", "some-mcp@1.2.3"}, nil, []AttachedFile{checked}},
		"bunx --bun":                            {"bunx", []string{"--bun", "some-mcp"}, nil, []AttachedFile{checked}},
		"uvx unpinned":                          {"uvx", []string{"mcp-server-git", "--repository", "."}, nil, []AttachedFile{checked}},
		"uvx, .npmrc is not uv's":               {"uvx", uvx, nil, []AttachedFile{checked, local(".npmrc")}},
		"uvx --from git+https":                  {"uvx", []string{"--from", "git+https://github.com/example/mcp-x", "mcp-x"}, nil, []AttachedFile{checked}},
		"uvx --python 3.12 --with pkg":          {"uvx", []string{"--python", "3.12", "--with", "requests>=2,httpx", "mcp-server-fetch==2025.4.7"}, nil, []AttachedFile{checked}},
		"uvx tool@version":                      {"uvx", []string{"mcp-server-time@0.6.2"}, nil, []AttachedFile{checked}},
		"pipx run":                              {"pipx", []string{"run", "--spec", "mcp-server-git==1.0", "mcp-server-git"}, nil, []AttachedFile{checked}},
		"server env not code-loading":           {"npx", npx, map[string]string{"GITHUB_TOKEN": "x", "NODE_ENV": "production", "PYTHONUNBUFFERED": "1"}, []AttachedFile{checked}},
		"docker run, no mount (GAP-0575)":       {"docker", []string{"run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"}, nil, nil},
		"podman run --env=X --name=n":           {"/usr/bin/podman", []string{"run", "-i", "--rm", "--env=TOKEN", "--name=n", "mcp/fetch:latest", "--stdio"}, nil, nil},
		"installed program, project as data":    {"/usr/local/bin/mcp-server-filesystem", []string{"/work/repo"}, nil, nil},
		"bare name resolved outside (GAP-0575)": {"mcp-server-git", []string{"--repository", "."}, nil, []AttachedFile{{Role: RoleCommandPath, Path: "mcp-server-git", Content: []byte("/usr/local/bin/mcp-server-git")}}},
	}
	for name, r := range known {
		if d := repoServerDecision(t, r.cmd, r.args, r.env, r.files...); d.Unavailable {
			t.Errorf("%s: %+v, want decided by the config rules", name, d)
		}
	}
}
