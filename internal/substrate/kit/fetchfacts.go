// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
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
)

// fetchMarkers are project configs that change what a fetcher runs or
// where it fetches from (the registry, node options, a preload script, an
// index or find-links).
var fetchMarkers = []string{".npmrc", ".yarnrc", ".yarnrc.yml", "bunfig.toml", "pip.conf", "pip.ini", "uv.toml"}

const (
	maxFetchNames = 4096
	maxFetchDirs  = 64
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
