//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// agentConfigOwner is a variable so a test can stand in for the root-owned
// files it cannot create as an ordinary user. It reads the owner and the link
// count of a file or folder that lstat described.
var agentConfigOwner = func(info os.FileInfo) (uid uint32, links uint64, ok bool) {
	stat, isStat := info.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, 0, false
	}
	return stat.Uid, uint64(stat.Nlink), true
}

// RootOwnedAgentConfigPaths lists what the recovery chain has to return to the
// account so the agent config files DefenseClaw patches for it (the hook config
// and the patched files of every built-in connector) are usable again: a
// regular file in the account home that root owns, or the outermost folder
// above such a file that root owns. A gateway run as root wrote them before the
// writers kept the account as the owner (GAP-0848); the account cannot read or
// replace a root-owned file, and cannot create the atomic temp file in a
// root-owned folder. A folder is listed whole because a root-owned 0700 folder
// hides what it holds from this scan.
//
// The scan walks each path from the physical home one name at a time with lstat
// and stops at a link, so a path that runs through a linked folder, a linked
// file, or a file with more than one hard link (the same inode may live outside
// the home) is never listed. A file outside the home (a machine-wide config) is
// root-owned by design and is not listed either.
func RootOwnedAgentConfigPaths(dataDir string) []string {
	if os.Geteuid() == 0 {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return nil
	}
	home = filepath.Clean(home)
	physicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return nil
	}
	opts := SetupOpts{DataDir: dataDir}
	seen := map[string]struct{}{}
	var found []string
	registry := NewDefaultRegistry()
	for _, name := range registry.Names() {
		conn, ok := registry.Get(name)
		if !ok {
			continue
		}
		candidates := HookConfigPathsForConnector(conn, opts)
		if provider, ok := conn.(AgentPathProvider); ok {
			candidates = append(candidates, provider.AgentPaths(opts).PatchedFiles...)
		}
		for _, path := range candidates {
			path = filepath.Clean(path)
			if !filepath.IsAbs(path) || path == home || !managedPathWithin(path, home) {
				continue
			}
			rel, err := filepath.Rel(home, path)
			if err != nil {
				continue
			}
			owned := rootOwnedUnder(physicalHome, strings.Split(rel, string(filepath.Separator)))
			if _, dup := seen[owned]; owned == "" || dup {
				continue
			}
			seen[owned] = struct{}{}
			found = append(found, owned)
		}
	}
	sort.Strings(found)
	return found
}

// rootOwnedUnder walks names below dir and returns the first root-owned folder
// on the way, or the last name when it is a root-owned file with one link. It
// returns "" at the first name that is missing, unreadable or a link.
func rootOwnedUnder(dir string, names []string) string {
	for i, name := range names {
		dir = filepath.Join(dir, name)
		info, err := os.Lstat(dir)
		if err != nil {
			return ""
		}
		uid, links, known := agentConfigOwner(info)
		if !known {
			return ""
		}
		if i == len(names)-1 {
			if info.Mode().IsRegular() && uid == 0 && links == 1 {
				return dir
			}
			return ""
		}
		if !info.IsDir() {
			return ""
		}
		if uid == 0 {
			return dir
		}
	}
	return ""
}
