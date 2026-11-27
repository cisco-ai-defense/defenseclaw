// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Roles of the folder facts a registry fetcher (npx, pnpx, bunx, uvx,
// pipx) depends on (GAP-0573). The gateway counts a fetched server as not
// known to run nothing of the folder unless the kit looked (fetch_checked)
// and found nothing the fetcher would resolve locally.
const (
	// roleFetchChecked records that the kit looked; Path is the folder.
	roleFetchChecked = "mcp_fetch_checked"
	// roleFetchLocal is a project config a fetcher reads (.npmrc,
	// bunfig.toml, pip.conf, uv.toml) or a package.json the kit could not
	// attach; Path is the file.
	roleFetchLocal = "mcp_fetch_local"
	// roleFetchConfig is a package.json of the folder or a parent, with
	// its content (its bin, name and workspaces decide).
	roleFetchConfig = "mcp_fetch_config"
	// roleFetchNames lists node_modules (package names, and .bin/<name>
	// for every program in node_modules/.bin), one per line; Truncated
	// when the list is cut or unreadable.
	roleFetchNames = "mcp_fetch_names"
	// roleCommandPath is where the actor's PATH finds a bare server
	// command; Path is the command, Content its resolved absolute path.
	roleCommandPath = "mcp_command_path"
	// roleCommandPathHit is the PATH entry itself (absolute, no link
	// followed) when it differs from roleCommandPath: a link of the
	// folder is the folder's, whatever it points at (GAP-0632).
	roleCommandPathHit = "mcp_command_path_hit"
	// roleFetchBins lists the programs the packages in the actor's npx
	// cache declare (their package.json bin), "<package>\t<program>" one
	// per line; Path is the cache folder (GAP-0636). Truncated when the
	// list is cut: the gateway still reads every line it has.
	roleFetchBins = "mcp_fetch_bins"
)

// fetchMarkers are project configs that change what a fetcher runs or
// where it fetches from (the registry, node options, a preload script, an
// index or find-links).
var fetchMarkers = []string{".npmrc", ".yarnrc", ".yarnrc.yml", "bunfig.toml", "pip.conf", "pip.ini", "uv.toml"}

const (
	maxFetchNames = 4096
	maxFetchDirs  = 64
	// maxNpxDirs bounds the npx cache folders the kit reads (one per
	// fetched package spec).
	maxNpxDirs = 512
)

// attachFetchFacts reports, once per event, what the folder and its
// parents (up to the home folder or the root, not included) offer a
// registry fetcher: the configs it reads, every package.json, and the
// names in node_modules. npx runs a project's own program of the same name
// (package.json bin, node_modules/.bin in the folder or a parent) and
// reads the project's .npmrc (node-options), pinned or not (GAP-0573).
func attachFetchFacts(f *Facts, cwd string, budget int64) int64 {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return budget
	}
	for _, a := range f.Files {
		if a.Role == roleFetchChecked {
			return budget
		}
	}
	f.Files = append(f.Files, AttachedFile{Role: roleFetchChecked, Path: cwd})
	home, _ := os.UserHomeDir()
	if home != "" {
		home = filepath.Clean(home)
	}
	for _, c := range npmCacheDirs(home) {
		if a, ok := npxCacheBins(filepath.Join(c, "_npx")); ok {
			f.Files = append(f.Files, a)
		}
	}
	dir := filepath.Clean(cwd)
	for n := 0; n < maxFetchDirs; n++ {
		for _, m := range fetchMarkers {
			p := filepath.Join(dir, m)
			if _, err := os.Lstat(p); err == nil {
				f.Files = append(f.Files, AttachedFile{Role: roleFetchLocal, Path: p})
			}
		}
		if p := filepath.Join(dir, "package.json"); exists(p) {
			before := len(f.Files)
			budget = attach(f, roleFetchConfig, p, "", budget)
			if len(f.Files) == before {
				// There, but not a readable regular file: not known.
				f.Files = append(f.Files, AttachedFile{Role: roleFetchLocal, Path: p})
			}
		}
		if p := filepath.Join(dir, "node_modules"); exists(p) {
			f.Files = append(f.Files, nodeModulesNames(p))
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == home || isRoot(parent) {
			break
		}
		dir = parent
	}
	return budget
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func isRoot(p string) bool { return filepath.Dir(p) == p }

// nodeModulesNames lists the packages of a node_modules folder (@scope/name
// for a scope) and its programs (.bin/<name>).
func nodeModulesNames(dir string) AttachedFile {
	a := AttachedFile{Role: roleFetchNames, Path: dir}
	var names []string
	add := func(n string) {
		if len(names) >= maxFetchNames {
			a.Truncated = true
			return
		}
		names = append(names, n)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.Truncated = true
	}
	for _, e := range entries {
		switch n := e.Name(); {
		case n == ".bin":
			bins, err := os.ReadDir(filepath.Join(dir, n))
			if err != nil {
				a.Truncated = true
			}
			for _, b := range bins {
				add(".bin/" + b.Name())
			}
		case strings.HasPrefix(n, "@"):
			scoped, err := os.ReadDir(filepath.Join(dir, n))
			if err != nil {
				a.Truncated = true
			}
			for _, s := range scoped {
				add(n + "/" + s.Name())
			}
		case strings.HasPrefix(n, "."):
		default:
			add(n)
		}
	}
	if !a.Truncated {
		// A cut list is sent empty: it is not known.
		sort.Strings(names)
		a.Content = []byte(strings.Join(names, "\n"))
	}
	a.Size = int64(len(a.Content))
	sum := sha256.Sum256(a.Content)
	a.SHA256 = hex.EncodeToString(sum[:])
	return a
}

// attachCommandPath records where the actor's PATH finds a bare server
// command (a name with no separator), resolved through links, so the
// gateway can tell an installed program from one of the folder, and, when
// a link was followed, the PATH entry itself (GAP-0632).
func attachCommandPath(f *Facts, cmd string) {
	if cmd == "" || strings.ContainsAny(cmd, `/\`) {
		return
	}
	for _, a := range f.Files {
		if a.Role == roleCommandPath && a.Path == cmd {
			return
		}
	}
	p, err := exec.LookPath(cmd)
	if err != nil {
		return
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	hit := p
	if r, err := winpath.EvalLinks(p); err == nil {
		p = r
	}
	sum := sha256.Sum256([]byte(p))
	f.Files = append(f.Files, AttachedFile{Role: roleCommandPath, Path: cmd, Resolved: p, Content: []byte(p),
		Size: int64(len(p)), SHA256: hex.EncodeToString(sum[:])})
	if hit != p {
		sum := sha256.Sum256([]byte(hit))
		f.Files = append(f.Files, AttachedFile{Role: roleCommandPathHit, Path: cmd, Resolved: p, Content: []byte(hit),
			Size: int64(len(hit)), SHA256: hex.EncodeToString(sum[:])})
	}
}

// npmCacheDirs are the npm cache folders of the actor: the one its
// environment names (npm reads npm_config_cache in any case) and the
// default one (~/.npm, or %LocalAppData%\npm-cache on Windows). A cache
// set only in an .npmrc is not read; the gateway then keeps its guess of
// the program names (GAP-0636).
func npmCacheDirs(home string) []string {
	var out []string
	add := func(p string) {
		if p == "" || !filepath.IsAbs(p) {
			return
		}
		p = filepath.Clean(p)
		for _, o := range out {
			if o == p {
				return
			}
		}
		out = append(out, p)
	}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, "npm_config_cache") {
			add(v)
		}
	}
	if runtime.GOOS == "windows" {
		if l := os.Getenv("LOCALAPPDATA"); l != "" {
			add(filepath.Join(l, "npm-cache"))
		}
	} else if home != "" {
		add(filepath.Join(home, ".npm"))
	}
	return out
}

// npxCacheBins lists the programs that the packages npx fetched before
// declare: for every npx cache folder (<cache>/_npx/<hash>), the packages
// its package.json depends on and, from each one's installed package.json,
// the names of its bin (an object's keys, a string's package base name,
// the files of directories.bin). The gateway counts a node_modules/.bin
// entry of the project with one of those names against a server that
// fetches the package, so a declared program outside the names it guesses
// is no longer missed (GAP-0636). The agent can edit its own cache, but a
// name it removes only brings back the guess and a name it adds only
// counts more of the folder: never weaker than without the list. A package
// npx has not fetched yet is not in the cache (the first run keeps the
// guess). ok is false when there is no npx cache folder.
func npxCacheBins(dir string) (AttachedFile, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return AttachedFile{}, false
	}
	a := AttachedFile{Role: roleFetchBins, Path: dir}
	seen := map[string]bool{}
	var lines []string
	add := func(pkg, bin string) {
		bin = path.Base(strings.ReplaceAll(strings.TrimSpace(bin), "\\", "/"))
		if bin == "" || bin == "." || bin == "/" || strings.ContainsAny(bin+pkg, "\t\r\n") {
			return
		}
		l := pkg + "\t" + bin
		if seen[l] {
			return
		}
		if len(lines) >= maxFetchNames {
			a.Truncated = true
			return
		}
		seen[l] = true
		lines = append(lines, l)
	}
	if len(entries) > maxNpxDirs {
		entries, a.Truncated = entries[:maxNpxDirs], true
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		root := filepath.Join(dir, e.Name())
		var top struct {
			Dependencies map[string]string `json:"dependencies"`
		}
		if json.Unmarshal(readSmall(filepath.Join(root, "package.json")), &top) != nil {
			continue
		}
		for pkg := range top.Dependencies {
			if !npmPackageName(pkg) {
				continue
			}
			pdir := filepath.Join(root, "node_modules", filepath.FromSlash(pkg))
			var pj struct {
				Bin         json.RawMessage `json:"bin"`
				Directories struct {
					Bin string `json:"bin"`
				} `json:"directories"`
			}
			if json.Unmarshal(readSmall(filepath.Join(pdir, "package.json")), &pj) != nil {
				continue
			}
			var one string
			var many map[string]string
			switch {
			case len(pj.Bin) == 0:
				// npm links every file of directories.bin when there is no bin.
				if d := pj.Directories.Bin; d != "" {
					if bdir := filepath.Join(pdir, filepath.FromSlash(d)); within(bdir, pdir) {
						bins, _ := os.ReadDir(bdir)
						for _, b := range bins {
							if !b.IsDir() {
								add(pkg, b.Name())
							}
						}
					}
				}
			case json.Unmarshal(pj.Bin, &one) == nil:
				// A string bin is named after the package's base name.
				if one != "" {
					add(pkg, path.Base(pkg))
				}
			case json.Unmarshal(pj.Bin, &many) == nil:
				for n := range many {
					add(pkg, n)
				}
			}
		}
	}
	sort.Strings(lines)
	a.Content = []byte(strings.Join(lines, "\n"))
	a.Size = int64(len(a.Content))
	sum := sha256.Sum256(a.Content)
	a.SHA256 = hex.EncodeToString(sum[:])
	return a, true
}

// npmPackageName reports a plain registry package name (name or
// @scope/name), never a path out of node_modules.
func npmPackageName(p string) bool {
	part := func(s string) bool { return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\:`) }
	if rest, ok := strings.CutPrefix(p, "@"); ok {
		scope, name, ok := strings.Cut(rest, "/")
		return ok && part(scope) && part(name)
	}
	return part(p)
}
