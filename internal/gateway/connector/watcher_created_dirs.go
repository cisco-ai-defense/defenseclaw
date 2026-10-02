// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// watcherCreatedDirsFile, in the DefenseClaw data directory, lists the
// folders DefenseClaw created because they were missing: those the gateway's
// install watcher started watching, and the parents of the agent config files
// a connector setup wrote. Uninstall removes the ones still empty
// (cli/defenseclaw/commands/cmd_uninstall.py _remove_created_dirs).
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

// SetupRecordingCreatedDirs runs conn.Setup and adds to the data directory's
// list the folders below the home directory that it created for the agent
// config files the connector owns (~/.copilot/hooks, say), so uninstall can
// remove them again while they are empty. The list is best effort: Setup's
// own result is what it returns.
func SetupRecordingCreatedDirs(ctx context.Context, conn Connector, opts SetupOpts) error {
	missing := missingConfigDirs(conn, opts)
	err := conn.Setup(ctx, opts)
	recordDirsNowPresent(opts.DataDir, missing)
	return err
}

// recordDirsNowPresent adds to the data directory's list each of missing,
// folders that did not exist before a DefenseClaw write, that is a folder
// now. Best effort.
func recordDirsNowPresent(dataDir string, missing []string) {
	if strings.TrimSpace(dataDir) == "" {
		return
	}
	var created []string
	for _, dir := range missing {
		if info, statErr := os.Lstat(dir); statErr == nil && info.Mode().Type() == fs.ModeDir {
			created = append(created, dir)
		}
	}
	if len(created) > 0 {
		_ = recordCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile), created)
	}
}

// prepareOpenCodePluginArtifactDestination creates the plugin folder of
// path (~/.config/opencode/plugins) and records the folders below the home
// it had to create, so uninstall removes them again once they are empty:
// the folder is made before any connector Setup runs (the gateway's
// registration snapshot), so SetupRecordingCreatedDirs never sees it
// missing, and the plugin file is not one of the hook config paths.
func prepareOpenCodePluginArtifactDestination(path, dataDir string) error {
	var missing []string
	if home := strings.TrimSpace(userHomeDir()); home != "" && filepath.IsAbs(path) {
		missing = missingParentDirs(filepath.Clean(home), path)
	}
	err := createOpenCodePluginArtifactDestination(path)
	recordDirsNowPresent(dataDir, missing)
	return err
}

// RemovalLeavingNoNewDirs runs fn, a removal of conn's registration for a
// target that may never have had DefenseClaw's per-user state. When the data
// directory did not exist, what fn put there (the disabled hook scripts and
// locks a teardown writes so an agent's cached registration stays harmless;
// none can be cached, as no hook script was ever there) goes again, and so do
// the agent config folders below the home it created and left empty.
func RemovalLeavingNoNewDirs(conn Connector, opts SetupOpts, fn func() error) error {
	dataDir := filepath.Clean(strings.TrimSpace(opts.DataDir))
	_, statErr := os.Lstat(dataDir)
	dataDirMissing := strings.TrimSpace(opts.DataDir) != "" && errors.Is(statErr, fs.ErrNotExist)
	missing := missingConfigDirs(conn, opts)
	err := fn()
	if !dataDirMissing {
		return err
	}
	if info, statErr := os.Lstat(dataDir); statErr == nil && info.IsDir() {
		if removeErr := os.RemoveAll(dataDir); removeErr != nil && err == nil {
			err = removeErr
		}
	}
	sort.Slice(missing, func(i, j int) bool { return len(missing[i]) > len(missing[j]) })
	for _, dir := range missing {
		_ = os.Remove(dir) // only empty folders go
	}
	return err
}

// missingConfigDirs returns the missing folders between the home directory
// and each agent config file conn writes, deepest first.
func missingConfigDirs(conn Connector, opts SetupOpts) []string {
	home := strings.TrimSpace(userHomeDir())
	if home == "" || conn == nil {
		return nil
	}
	home = filepath.Clean(home)
	var missing []string
	for _, path := range HookConfigPathsForConnector(conn, opts) {
		if !filepath.IsAbs(path) {
			continue
		}
		missing = append(missing, missingParentDirs(home, path)...)
	}
	return missing
}

// missingParentDirs returns the missing folders between home and path,
// deepest first.
func missingParentDirs(home, path string) []string {
	var missing []string
	for dir := filepath.Dir(filepath.Clean(path)); belowDir(home, dir); dir = filepath.Dir(dir) {
		if _, statErr := os.Lstat(dir); !errors.Is(statErr, fs.ErrNotExist) {
			break
		}
		missing = append(missing, dir)
	}
	return missing
}

// belowDir reports whether path is strictly inside root.
func belowDir(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
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
