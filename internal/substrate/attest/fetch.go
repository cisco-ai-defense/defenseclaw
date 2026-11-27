// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Folder facts the kit reports for a registry fetcher (GAP-0573); see
// internal/substrate/kit/fetchfacts.go.
const (
	RoleFetchChecked = "mcp_fetch_checked"
	RoleFetchLocal   = "mcp_fetch_local"
	RoleFetchConfig  = "mcp_fetch_config"
	RoleFetchNames   = "mcp_fetch_names"
	RoleCommandPath  = "mcp_command_path"
	// RoleCommandPathHit is the PATH entry of a bare command before links
	// are followed, when it differs from RoleCommandPath (GAP-0632).
	RoleCommandPathHit = "mcp_command_path_hit"
)

// fetchFamily is the package ecosystem of a fetcher.
var fetchFamily = map[string]string{"npx": "npm", "pnpx": "npm", "bunx": "npm", "uvx": "python", "pipx": "python"}

// fetchMarkerFamily are the project configs that change what a fetcher of
// the family runs or where it fetches from.
var fetchMarkerFamily = map[string]string{".npmrc": "npm", ".yarnrc": "npm", ".yarnrc.yml": "npm", "bunfig.toml": "npm",
	"package.json": "npm", "pip.conf": "python", "pip.ini": "python", "uv.toml": "python"}

// fetchOpt is how a fetcher option is read: a flag that changes nothing of
// what runs, or an option whose value is a registry package or a Python
// version. Every other option (-c, --call, --with-editable, --find-links,
// --index-url, --directory, --spec ./x, an option the gateway does not
// know) means the server is not known (GAP-0573).
type fetchOpt int

const (
	optFlag   fetchOpt = iota + 1
	optAny             // a value that does not change what runs (a log level)
	optPkg             // a registry package (the server's package)
	optWith            // registry packages added beside it (comma-separated)
	optPython          // a Python version
)

var fetchOpts = map[string]map[string]fetchOpt{
	"npm": {"-y": optFlag, "--yes": optFlag, "-q": optFlag, "--quiet": optFlag, "--silent": optFlag, "--no": optFlag,
		"--prefer-offline": optFlag, "--prefer-online": optFlag, "--offline": optFlag, "--no-update-notifier": optFlag,
		"--no-fund": optFlag, "--no-audit": optFlag, "--bun": optFlag, "--loglevel": optAny,
		"-p": optPkg, "--package": optPkg},
	"uvx": {"-q": optFlag, "--quiet": optFlag, "-v": optFlag, "--verbose": optFlag, "--offline": optFlag, "--no-cache": optFlag,
		"-n": optFlag, "--isolated": optFlag, "--refresh": optFlag, "--no-progress": optFlag, "--native-tls": optFlag,
		"--no-config": optFlag, "--color": optAny, "--from": optPkg, "--with": optWith, "-p": optPython, "--python": optPython},
	"pipx": {"-q": optFlag, "--quiet": optFlag, "-v": optFlag, "--verbose": optFlag, "--no-cache": optFlag,
		"--spec": optPkg, "--python": optPython},
}

var (
	npmSpecRE = regexp.MustCompile(`(?i)^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*(@[a-z0-9._~^<>=*|+-]+)?$`)
	pySpecRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?((@|==|>=|<=|~=|!=|>|<)[A-Za-z0-9.*+!_-]+(,(==|>=|<=|~=|!=|>|<)[A-Za-z0-9.*+!_-]+)*)?$`)
	pyVerRE   = regexp.MustCompile(`(?i)^((cpython|pypy|python)[-@]?)?[0-9]+(\.[0-9]+){0,2}$`)
	binNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// registrySpec reports a package spec that resolves to the registry (or a
// remote https source), never to the folder: no path, file:, link:,
// git+file:, alias or shorthand.
func registrySpec(family, v string) bool {
	if strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "git+https://") {
		return !strings.ContainsAny(v, " \t") && !strings.Contains(v, "..")
	}
	if family == "npm" {
		return npmSpecRE.MatchString(v)
	}
	return pySpecRE.MatchString(v)
}

// specName is the package name of a registry spec: no version, no extras.
func specName(family, v string) string {
	if family == "npm" {
		if i := strings.LastIndex(v, "@"); i > 0 {
			return v[:i]
		}
		return v
	}
	if i := strings.IndexAny(v, "[=<>!~@"); i > 0 {
		return v[:i]
	}
	return v
}

// fetchedRunner reports a fetched package that runs code it is given (tsx
// -e, python -c, node): what it runs is not known.
func fetchedRunner(name string) bool {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)
	return runners[name] || strings.HasPrefix(name, "python3.") || strings.HasPrefix(name, "pypy")
}

// fetchRunsNothingOfFolder reports a server started by a registry fetcher
// that is known to run nothing of the folder (GAP-0573): every option is
// one the gateway reads, the package (and every package added beside it)
// resolves to the registry, the package is not a runner given code, and
// the kit looked at the folder and found nothing the fetcher resolves
// locally (a package.json bin or workspaces, node_modules/.bin, the package
// itself in node_modules, an .npmrc, pip.conf or uv.toml). An unpinned
// name in a clean folder is the config rules' warning.
func fetchRunsNothingOfFolder(base string, args []string, project string, files []AttachedFile) bool {
	family := fetchFamily[base]
	opts := fetchOpts["npm"]
	switch base {
	case "uvx":
		opts = fetchOpts["uvx"]
	case "pipx":
		// Only pipx run starts a package; its subcommand comes first.
		if len(args) == 0 || args[0] != "run" {
			return false
		}
		args, opts = args[1:], fetchOpts["pipx"]
	}
	var pkgs []string // registry packages the server fetches
	var command string
	pkgOpt := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				command = args[i+1]
			}
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			command = a
			break
		}
		name, val, inline := strings.Cut(a, "=")
		kind := opts[name]
		if kind == 0 {
			return false // an option the gateway does not read
		}
		if kind == optFlag {
			if inline {
				return false
			}
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				return false
			}
			i++
			val = args[i]
		}
		switch kind {
		case optPkg:
			if !registrySpec(family, val) {
				return false
			}
			pkgs, pkgOpt = append(pkgs, val), true
		case optWith:
			for _, v := range strings.Split(val, ",") {
				if !registrySpec(family, strings.TrimSpace(v)) {
					return false
				}
				pkgs = append(pkgs, strings.TrimSpace(v))
			}
		case optPython:
			if !pyVerRE.MatchString(val) {
				return false // a path to an interpreter, or a form not read
			}
		}
	}
	if command == "" {
		return false
	}
	if pkgOpt {
		// --package/--from/--spec name the package; the operand is the
		// program of it to run, a plain name.
		if !binNameRE.MatchString(command) || fetchedRunner(command) {
			return false
		}
	} else {
		if !registrySpec(family, command) {
			return false
		}
		pkgs = append(pkgs, command)
	}
	for _, p := range pkgs {
		if fetchedRunner(specName(family, p)) {
			return false
		}
	}
	return fetchFolderClean(family, project, pkgs, command, files)
}

// fetchFolderClean reports that the kit looked at the folder and found
// nothing a fetcher of the family would resolve there.
func fetchFolderClean(family, project string, pkgs []string, command string, files []AttachedFile) bool {
	checked := false
	names := map[string]bool{command: true}
	for _, p := range pkgs {
		names[p], names[specName(family, p)] = true, true
	}
	for _, f := range files {
		switch f.Role {
		case RoleFetchChecked:
			if path.Clean("/"+filepath.ToSlash(f.Path)) == project {
				checked = true
			}
		case RoleFetchLocal:
			if fetchMarkerFamily[path.Base(filepath.ToSlash(f.Path))] == family {
				return false
			}
		case RoleFetchConfig:
			if family == "npm" && !packageJSONClean(f, names) {
				return false
			}
		case RoleFetchNames:
			if family != "npm" {
				continue
			}
			if f.Truncated {
				return false
			}
			for _, n := range strings.Split(string(f.Content), "\n") {
				// The package itself in node_modules is run from there.
				if names[n] {
					return false
				}
				// npx puts node_modules/.bin first on PATH, so a program
				// there can stand in for the fetched package's program or
				// for the runtime its script starts. The project's other
				// tools (tsc, eslint) change nothing.
				if b, ok := strings.CutPrefix(n, ".bin/"); ok && binShadows(b, names, pkgs, family) {
					return false
				}
			}
		}
	}
	return checked
}

// fetchRuntimes are the programs npx, or the script of a fetched npm
// package, start through PATH (#!/usr/bin/env node, the run-script shell).
var fetchRuntimes = map[string]bool{"node": true, "nodejs": true, "bun": true, "deno": true, "sh": true, "bash": true,
	"env": true, "npm": true, "npx": true, "pnpm": true, "pnpx": true, "bunx": true, "yarn": true, "corepack": true}

// binShadows reports a node_modules/.bin program that npx could run in
// place of the fetched package's program or of the runtime it starts: a
// name of the server, a runtime, or a program name the package commonly
// declares (binNamesOf). Whole names only, compared without case and
// without the Windows shim suffixes: a vendor's own CLI beside its MCP
// server (.bin/playwright beside @playwright/mcp) is not one of them.
func binShadows(bin string, names map[string]bool, pkgs []string, family string) bool {
	b := strings.ToLower(bin)
	for _, ext := range []string{".cmd", ".ps1", ".exe", ".bat"} {
		b = strings.TrimSuffix(b, ext)
	}
	if b == "" {
		return false
	}
	if fetchRuntimes[b] {
		return true
	}
	for n := range names {
		if strings.EqualFold(n, bin) || strings.EqualFold(n, b) {
			return true
		}
	}
	for _, p := range pkgs {
		if binNamesOf(strings.ToLower(specName(family, p)))[b] {
			return true
		}
	}
	return false
}

// binNamesOf lists the program names a registry package commonly declares:
// its name, its base name, mcp-<base> for a server-<x> base, and for a
// scoped package <scope>-<base> and mcp-server-<scope>
// (@modelcontextprotocol/server-filesystem declares mcp-server-filesystem).
func binNamesOf(name string) map[string]bool {
	out := map[string]bool{name: true}
	scope, base := "", name
	if s, r, ok := strings.Cut(strings.TrimPrefix(name, "@"), "/"); ok && strings.HasPrefix(name, "@") {
		scope, base = s, r
	}
	out[base] = true
	if strings.HasPrefix(base, "server-") {
		out["mcp-"+base] = true
	}
	if scope != "" {
		out[scope+"-"+base] = true
		out["mcp-server-"+scope] = true
	}
	return out
}

// packageJSONClean reports a package.json that gives npx nothing of the
// folder to run: no bin, no workspaces, not the fetched package itself.
func packageJSONClean(f AttachedFile, names map[string]bool) bool {
	if f.Truncated {
		return false
	}
	var pj struct {
		Name       string          `json:"name"`
		Bin        json.RawMessage `json:"bin"`
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if json.Unmarshal(f.Content, &pj) != nil {
		return false
	}
	empty := func(r json.RawMessage) bool {
		s := strings.TrimSpace(string(r))
		return s == "" || s == "null" || s == "{}" || s == "[]" || s == `""`
	}
	return empty(pj.Bin) && empty(pj.Workspaces) && !names[pj.Name]
}

// commandPath is where the kit found a bare command on the actor's PATH
// (role RoleCommandPath: links followed; RoleCommandPathHit: the PATH
// entry itself), or "" when it did not report one.
func commandPath(role, cmd string, files []AttachedFile) string {
	for _, f := range files {
		if f.Role == role && f.Path == cmd {
			if p := filepath.ToSlash(string(f.Content)); path.IsAbs(p) {
				return path.Clean(p)
			}
		}
	}
	return ""
}

// containerRun reports a docker or podman run of a registry image that sees
// nothing of the folder: no mount, working folder, env file, entry point or
// option the gateway does not read (GAP-0575). What runs is the image's.
func containerRun(args []string) bool {
	if len(args) == 0 || args[0] != "run" {
		return false
	}
	flags := map[string]bool{"-i": true, "--interactive": true, "--rm": true, "-t": true, "--tty": true, "-it": true, "-ti": true,
		"--init": true, "--read-only": true}
	values := map[string]bool{"-e": true, "--env": true, "--name": true, "--pull": true, "--platform": true, "-u": true, "--user": true,
		"--memory": true, "-m": true, "--cpus": true, "-l": true, "--label": true, "--network": true, "--net": true, "--hostname": true, "-h": true}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			img := filepath.ToSlash(a)
			return img != "" && !strings.HasPrefix(img, ".") && !path.IsAbs(img) && !strings.Contains(img, "..")
		}
		name, _, inline := strings.Cut(a, "=")
		switch {
		case flags[name] && !inline:
		case values[name]:
			if !inline {
				i++
			}
		default:
			return false // -v, --mount, -w, --env-file, --entrypoint, --privileged, ...
		}
	}
	return false
}
