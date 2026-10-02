// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// watcherCreatedDirsFile, in the DefenseClaw data directory, lists the
// folders the gateway's install watcher created because they were missing
// when it started watching them.
const (
	watcherCreatedDirsFile     = "watcher-created-dirs.json"
	watcherCreatedDirsMaxBytes = 1 << 20
)

type watcherCreatedDirs struct {
	Dirs []string `json:"dirs"`
}

// RecordWatcherCreatedDirs adds dirs, absolute paths the install watcher just
// created, to the data directory's list, so a teardown can remove them again
// while they are still empty.
func RecordWatcherCreatedDirs(dataDir string, dirs []string) error {
	if strings.TrimSpace(dataDir) == "" || len(dirs) == 0 {
		return nil
	}
	return recordCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile), dirs)
}

// recordCreatedDirs adds dirs to the created-folder list at path.
func recordCreatedDirs(path string, dirs []string) error {
	record := readWatcherCreatedDirs(path)
	known := make(map[string]struct{}, len(record.Dirs)+len(dirs))
	for _, dir := range record.Dirs {
		known[dir] = struct{}{}
	}
	for _, dir := range dirs {
		dir = filepath.Clean(dir)
		if _, seen := known[dir]; seen || !filepath.IsAbs(dir) {
			continue
		}
		known[dir] = struct{}{}
		record.Dirs = append(record.Dirs, dir)
	}
	return writeWatcherCreatedDirs(path, record.Dirs)
}

// RemoveOpenCodeWatcherCreatedDirs removes the folders the install watcher
// created below the OpenCode config folder that are still empty. Only the
// explicit `connector teardown` calls it, which uninstall runs after stopping
// the gateway. A teardown inside a running gateway (guardrail disabled, or a
// failed setup's rollback) leaves them: that gateway's watcher still watches
// them and would miss what is installed there next.
func RemoveOpenCodeWatcherCreatedDirs(dataDir string) {
	removeWatcherCreatedDirs(dataDir, filepath.Dir(filepath.Dir(opencodePluginPath(SetupOpts{}))))
}

// removeWatcherCreatedDirs removes, deepest first, each listed folder below
// root that is still an empty folder reached through real folders from root.
// Anything else stays on disk: a folder that now has content, one replaced by
// a link or a file, and every folder outside root. It is best effort, and the
// list keeps only the folders outside root and those left with content.
func removeWatcherCreatedDirs(dataDir, root string) {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(root) == "" {
		return
	}
	removeCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile), root)
}

// removeCreatedDirs is removeWatcherCreatedDirs for the list at path.
func removeCreatedDirs(path, root string) {
	record := readWatcherCreatedDirs(path)
	if len(record.Dirs) == 0 {
		return
	}
	root = filepath.Clean(root)
	dirs := append([]string(nil), record.Dirs...)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	var kept []string
	for _, dir := range dirs {
		relative, err := filepath.Rel(root, dir)
		if err != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			kept = append(kept, dir)
			continue
		}
		if !realDirectoryChain(root, dir) {
			continue
		}
		if err := os.Remove(dir); err != nil {
			kept = append(kept, dir)
		}
	}
	if len(kept) == 0 {
		_ = os.Remove(path)
		return
	}
	_ = writeWatcherCreatedDirs(path, kept)
}

// realDirectoryChain reports whether dir and every folder between it and
// root is a plain directory, not a link, junction or file.
func realDirectoryChain(root, dir string) bool {
	for current := dir; current != root; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode().Type() != fs.ModeDir {
			return false
		}
		if filepath.Dir(current) == current {
			return false
		}
	}
	return true
}

func readWatcherCreatedDirs(path string) watcherCreatedDirs {
	var record watcherCreatedDirs
	data, err := safefile.ReadRegularFileBounded(path, watcherCreatedDirsMaxBytes)
	if err != nil || json.Unmarshal(data, &record) != nil {
		return watcherCreatedDirs{}
	}
	return record
}

func writeWatcherCreatedDirs(path string, dirs []string) error {
	sort.Strings(dirs)
	data, err := json.Marshal(watcherCreatedDirs{Dirs: dirs})
	if err != nil {
		return err
	}
	return safefile.Write(path, append(data, '\n'))
}
