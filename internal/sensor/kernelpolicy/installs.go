// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"path/filepath"
	"sort"
	"strings"
)

// Install is the resolved agent install of one enrolled (uid, connector).
// Only files that pass the per-user trust rule reach it, so a path another
// account can change never becomes an anchor.
type Install struct {
	UID       int
	Connector string
	// Native are the resolved ELF files of the agent itself (a native
	// Claude Code, a Rust Codex). They are safe to put in a binaries
	// anchor: no other program shares them.
	Native []string
	// Entries are the resolved entry files of script-hosted installs (an
	// npm Codex's wrapper, an uv-installed Python CLI). The process that
	// runs them is a shared interpreter, so they are recognized by what the
	// interpreter was asked to run and anchored by pid only, never by the
	// interpreter's path.
	Entries []string
}

// Resolved reports whether anything was found.
func (i Install) Resolved() bool { return len(i.Native)+len(i.Entries) > 0 }

// ResolveOptions carries the administrator's extra install prefixes
// (enrollment.agent_prefixes, DEFENSECLAW_TRUSTED_BIN_PREFIXES).
type ResolveOptions struct {
	ExtraPrefixes []string
}

const versionedDirLimit = 16

// ResolveInstalls resolves every enrolled CLI (uid, connector) to its real
// install files. Rows of connectors that are not CLIs, rows without a
// connector, and connectors with no trustworthy install resolve to an empty
// Install (and so to no anchor).
func ResolveInstalls(fsys FS, enrollment Enrollment, opts ResolveOptions) []Install {
	var out []Install
	seen := map[[2]any]bool{}
	for _, row := range enrollment.Rows {
		probe, ok := cliConnectors[row.Connector]
		if !ok {
			continue
		}
		key := [2]any{row.UID, row.Connector}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, resolveInstall(fsys, row, probe, opts))
	}
	return out
}

func resolveInstall(fsys FS, row Enrolled, probe cliProbe, opts ResolveOptions) Install {
	install := Install{UID: row.UID, Connector: row.Connector}
	home := row.Home
	if real, err := fsys.EvalSymlinks(home); err == nil {
		home = real
	}
	native, entries := map[string]bool{}, map[string]bool{}
	add := func(resolved string) {
		if fsys.IsELF(resolved) {
			native[resolved] = true
		} else {
			entries[resolved] = true
		}
	}
	for _, dir := range searchDirs(fsys, home, opts) {
		for _, binary := range probe.binaries {
			candidate := filepath.Join(dir, binary)
			if _, err := fsys.Lstat(candidate); err != nil {
				continue
			}
			resolved, ok := trustedExecutable(fsys, home, candidate, row.UID)
			if ok {
				add(resolved)
			}
		}
	}
	// Version directories hold every installed version side by side, so a
	// session that started before an auto-update keeps its anchor.
	for _, rel := range probe.versionDirs {
		dir := filepath.Join(home, filepath.FromSlash(rel))
		entriesInDir, err := fsys.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entriesInDir {
			candidate := filepath.Join(dir, entry.Name())
			resolved, ok := trustedExecutable(fsys, home, candidate, row.UID)
			if ok && fsys.IsELF(resolved) {
				native[resolved] = true
			}
		}
	}
	install.Native = sortedKeys(native)
	install.Entries = sortedKeys(entries)
	return install
}

// trustedExecutable resolves candidate and admits it only when it is a
// regular executable file that no other account can change.
//
// A candidate inside the user's home is the user's own file, and must stay
// there: a link the user controls must never be able to name a system
// program (a shell or interpreter) and pull ordinary processes into scope. A
// candidate outside the home (a machine prefix, an administrator's
// agent_prefixes) must be reached through a chain that Trusted admits for the
// uid, root-owned and not writable by anyone else.
func trustedExecutable(fsys FS, home, candidate string, uid int) (string, bool) {
	resolved, err := fsys.EvalSymlinks(candidate)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", false
	}
	info, err := fsys.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", false
	}
	if inside(home, candidate) {
		return resolved, inside(home, resolved)
	}
	if !fsys.Trusted(candidate, uid) || !fsys.Trusted(resolved, uid) {
		return "", false
	}
	return resolved, true
}

// searchDirs lists the directories an agent CLI is looked up in: the user's
// own install locations, then the machine prefixes. It mirrors the
// enumerator's search (UnixAgentSearchDirsFor) so the kernel scope and the
// hook enrollment agree about which install belongs to the user.
func searchDirs(fsys FS, home string, opts ResolveOptions) []string {
	dirs := []string{
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, ".npm-global", "bin"),
		filepath.Join(home, ".bun", "bin"),
		filepath.Join(home, ".opencode", "bin"),
		filepath.Join(home, "bin"),
		filepath.Join(home, ".npm-packages", "bin"),
		filepath.Join(home, ".volta", "bin"),
		filepath.Join(home, ".local", "share", "pnpm"),
		filepath.Join(home, ".yarn", "bin"),
		filepath.Join(home, ".config", "yarn", "global", "node_modules", ".bin"),
		filepath.Join(home, ".local", "share", "fnm", "aliases", "default", "bin"),
		filepath.Join(home, ".asdf", "shims"),
		filepath.Join(home, ".local", "share", "mise", "shims"),
		filepath.Join(home, ".linuxbrew", "bin"),
	}
	for _, pattern := range []string{
		filepath.Join(home, ".nvm", "versions", "node", "*", "bin"),
		filepath.Join(home, ".local", "share", "fnm", "node-versions", "*", "installation", "bin"),
		filepath.Join(home, ".asdf", "installs", "nodejs", "*", "bin"),
		filepath.Join(home, ".local", "share", "mise", "installs", "node", "*", "bin"),
	} {
		matches, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		sort.Sort(sort.Reverse(sort.StringSlice(matches)))
		if len(matches) > versionedDirLimit {
			matches = matches[:versionedDirLimit]
		}
		dirs = append(dirs, matches...)
	}
	dirs = append(dirs, "/usr/local/bin", "/usr/bin", "/home/linuxbrew/.linuxbrew/bin")
	for _, prefix := range opts.ExtraPrefixes {
		prefix = filepath.Clean(strings.TrimSpace(prefix))
		if filepath.IsAbs(prefix) && prefix != "/" {
			dirs = append(dirs, filepath.Join(prefix, "bin"))
		}
	}
	return dirs
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
