//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// agentConfigOwnerUID is a variable so a test can stand in for the root-owned
// files it cannot create as an ordinary user.
var agentConfigOwnerUID = func(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// RootOwnedAgentConfigFiles lists the agent config files DefenseClaw patches
// for the account (the hook config and the patched files of every built-in
// connector) that lie inside the account home and are owned by root while this
// process is not root. A gateway run as root wrote them before the writers kept
// the account as the owner (GAP-0848), and the account cannot read or replace
// them: the recovery chain returns them with the rest of the home. A file
// outside the home (a machine-wide config) is root-owned by design and is not
// listed. It reads with lstat only.
func RootOwnedAgentConfigFiles(dataDir string) []string {
	if os.Geteuid() == 0 {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return nil
	}
	home = filepath.Clean(home)
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
			if _, dup := seen[path]; dup || !filepath.IsAbs(path) || path == home || !managedPathWithin(path, home) {
				continue
			}
			seen[path] = struct{}{}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if uid, ok := agentConfigOwnerUID(info); ok && uid == 0 {
				found = append(found, path)
			}
		}
	}
	sort.Strings(found)
	return found
}
