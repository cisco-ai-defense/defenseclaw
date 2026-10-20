// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// DefaultVendorSystemRoots are the machine-wide trees agents read
// administrator policy and skills from: Codex /etc/codex, Cursor /etc/cursor,
// Copilot /etc/github-copilot, Claude Code and OpenCode under
// /Library/Application Support, and the %ProgramData% family on Windows.
// DefenseClaw only observes folders there: creating one changes the agent's
// own behavior (Codex treats an existing /etc/codex as an administrator
// policy layer and pauses when it cannot read it).
func DefaultVendorSystemRoots() []string {
	if runtime.GOOS == "windows" {
		var roots []string
		for _, name := range []string{"ProgramData", "ProgramFiles", "ProgramFiles(x86)", "SystemRoot"} {
			if value := strings.TrimSpace(os.Getenv(name)); value != "" {
				roots = append(roots, filepath.Clean(value))
			}
		}
		return roots
	}
	return []string{"/etc", "/private/etc", "/Library"}
}

// UnderVendorSystemRoot reports whether the absolute path lies under one of
// roots. The path is compared without resolving symlinks, so /etc/codex on
// macOS (where /etc links to /private/etc) matches through either spelling.
func UnderVendorSystemRoot(absolute string, roots []string) bool {
	cleaned := filepath.Clean(absolute)
	for _, root := range roots {
		root = filepath.Clean(root)
		if root == "" || root == "." || root == string(filepath.Separator) {
			continue
		}
		if runtime.GOOS == "windows" {
			if strings.EqualFold(cleaned, root) ||
				strings.HasPrefix(strings.ToLower(cleaned), strings.ToLower(root)+string(filepath.Separator)) {
				return true
			}
			continue
		}
		if cleaned == root || strings.HasPrefix(cleaned, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// RemoveVendorSystemCreatedDirs removes, deepest first, every folder the
// data directory's created-folders list places under one of roots that is
// still an empty real folder, and returns the ones removed. An older
// watcher created such folders (for example /etc/codex and
// /etc/codex/skills) when the gateway ran as root; removing them restores
// the agent's behavior (Codex reads no administrator policy from an absent
// /etc/codex). Folders with content, replaced by a link or a file, or that
// this process cannot remove stay on disk and in the list. Best effort.
func RemoveVendorSystemCreatedDirs(dataDir string, roots []string) []string {
	if strings.TrimSpace(dataDir) == "" || len(roots) == 0 {
		return nil
	}
	path := filepath.Join(dataDir, watcherCreatedDirsFile)
	record := readWatcherCreatedDirs(path)
	if len(record.Dirs) == 0 {
		return nil
	}
	dirs := append([]string(nil), record.Dirs...)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	var kept, removed []string
	for _, dir := range dirs {
		if !filepath.IsAbs(dir) || !UnderVendorSystemRoot(dir, roots) {
			kept = append(kept, dir)
			continue
		}
		info, err := os.Lstat(dir)
		if err != nil {
			continue // already gone
		}
		if info.Mode().Type() != fs.ModeDir {
			kept = append(kept, dir)
			continue
		}
		if err := os.Remove(dir); err != nil {
			kept = append(kept, dir)
			continue
		}
		removed = append(removed, dir)
	}
	if len(kept) == 0 {
		_ = os.Remove(path)
	} else {
		_ = writeWatcherCreatedDirs(path, kept)
	}
	return removed
}
