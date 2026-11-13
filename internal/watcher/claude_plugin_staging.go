// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// claudeStagingGrace is how long a Claude Code plugin install in flight (a
// staging folder, a <version>.linking-<pid> folder) is left alone; one that
// stays longer is scanned as a plugin, so a folder named like one is no
// scan hole.
const claudeStagingGrace = 15 * time.Minute

// claudeStagingName is Claude Code's own name for the folders it builds a
// plugin or clones a marketplace in, directly in plugins/cache:
// temp_<kind>_<unix ms>_<random>, with _x or .clone for some kinds. It is
// the pattern Claude Code's cache sweep uses (2.1.322), matched exactly and
// case-sensitively. Claude Code forbids only path separators, "." and ".."
// in a marketplace name, so the earlier tests (a temp_local_ prefix, a
// temp_subdir_*.clone name, any .git folder) let a marketplace named
// ".git" or "temp_subdir_a.clone" skip every scan (issue #1428 review).
var claudeStagingName = regexp.MustCompile(
	`^temp_(?:local|npm|github|git|subdir|archive|command|unknown)_(\d{10,})_[a-z0-9]{1,6}(?:_x|\.clone)?$`)

// claudeLinkingVersion is the <version>.linking-<pid> folder Claude Code
// fills before it renames it to <version>.
var claudeLinkingVersion = regexp.MustCompile(`^.+\.linking-\d+$`)

// claudeCacheEntry is what a path below Claude Code's plugin cache is, by
// its folder names alone.
type claudeCacheEntry int

const (
	// claudeCachePlugin is the cache's own <marketplace>/<plugin>/<version>
	// layout: read as plugins.
	claudeCachePlugin claudeCacheEntry = iota
	// claudeCacheStaging lies in a staging folder: in flight while fresh.
	claudeCacheStaging
	// claudeCacheStagingGit lies in the .git folder of a staging clone: git's
	// own files, never a plugin.
	claudeCacheStagingGit
	// claudeCacheLinking lies in a <version>.linking-<pid> folder: in flight
	// while fresh.
	claudeCacheLinking
)

// classifyClaudeCacheParts reads the folder names of a path relative to
// Claude Code's plugin cache. A .git folder counts only below a staging
// folder: as the marketplace, plugin or version part it is a plugin like
// any other.
func classifyClaudeCacheParts(parts []string) claudeCacheEntry {
	if len(parts) == 0 {
		return claudeCachePlugin
	}
	if claudeStagingName.MatchString(parts[0]) {
		if slices.Contains(parts[1:], ".git") {
			return claudeCacheStagingGit
		}
		return claudeCacheStaging
	}
	if len(parts) >= 3 && claudeLinkingVersion.MatchString(parts[2]) {
		return claudeCacheLinking
	}
	return claudeCachePlugin
}

// claudeStagingFresh reports a staging folder name whose time stamp is less
// than claudeStagingGrace old at now (a minute ahead is clock skew).
func claudeStagingFresh(name string, now time.Time) bool {
	match := claudeStagingName.FindStringSubmatch(name)
	if match == nil {
		return false
	}
	millis, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return false
	}
	age := now.Sub(time.UnixMilli(millis))
	return age > -time.Minute && age < claudeStagingGrace
}

// inClaudePluginStaging reports a path in a plugin cache that is a plugin
// install in flight, not a plugin. Claude Code builds a plugin in
// cache/temp_local_<ts>_<r>, clones a marketplace or a git plugin into
// cache/temp_<kind>_<ts>_<r>[.clone] and fills <version>.linking-<pid>
// before it moves the result to <marketplace>/<plugin>/<version>. The
// watcher read those as plugins (".git@temp_subdir_<n>.clone",
// "skills@temp_github_<n>"), found no manifest and quarantined them while
// Claude Code still wrote them, so the install or "claude plugin update"
// failed (GAP-0629, issue #1428). A name registered in known_marketplaces.json
// or installed_plugins.json is a marketplace, never staging. grace, when
// set, also bounds the staging folder's own age (the rescan). Codex keeps
// its cache as it was; the .dclaw-stage-<name>-<random> folder "defenseclaw
// plugin install" stages in is left alone in every cache (GAP-0017). The
// Secure Client profile keeps the earlier behaviour.
func (w *InstallWatcher) inClaudePluginStaging(path string, grace time.Duration) bool {
	if w.secureClientActive() {
		return false
	}
	root, parts, ok := w.claudeCacheParts(path)
	if !ok {
		return false
	}
	if isPluginStagingFolder(parts[0]) {
		return grace <= 0 || modifiedWithin(filepath.Join(root, parts[0]), grace)
	}
	if w.connectorForPath(root) != "claudecode" {
		return false
	}
	switch classifyClaudeCacheParts(parts) {
	case claudeCacheStagingGit:
		return !readClaudePluginRegistry(filepath.Dir(root)).marketplace(parts[0])
	case claudeCacheStaging:
		folder := filepath.Join(root, parts[0])
		return claudeStagingFresh(parts[0], time.Now()) &&
			(grace <= 0 || modifiedWithin(folder, grace)) &&
			!readClaudePluginRegistry(filepath.Dir(root)).marketplace(parts[0])
	case claudeCacheLinking:
		folder := filepath.Join(root, parts[0], parts[1], parts[2])
		return modifiedWithin(folder, claudeStagingGrace) &&
			!readClaudePluginRegistry(filepath.Dir(root)).installed(folder)
	}
	return false
}

// modifiedWithin reports a path last modified less than d ago.
func modifiedWithin(path string, d time.Duration) bool {
	info, err := os.Lstat(path)
	return err == nil && time.Since(info.ModTime()) < d
}

// claudePluginRegistry is what Claude Code registered next to its cache:
// marketplace names (known_marketplaces.json keys and the @marketplace part
// of installed_plugins.json ids, lower-cased) and install paths.
type claudePluginRegistry struct {
	marketplaces map[string]struct{}
	installPaths []string
}

// readClaudePluginRegistry reads pluginsRoot (the folder that holds cache).
// A missing or unreadable file registers nothing.
func readClaudePluginRegistry(pluginsRoot string) claudePluginRegistry {
	registry := claudePluginRegistry{marketplaces: map[string]struct{}{}}
	var known map[string]json.RawMessage
	if data, err := os.ReadFile(filepath.Join(pluginsRoot, "known_marketplaces.json")); err == nil &&
		json.Unmarshal(data, &known) == nil {
		for name := range known {
			registry.marketplaces[strings.ToLower(name)] = struct{}{}
		}
	}
	var installed struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	type install struct {
		InstallPath string `json:"installPath"`
	}
	if data, err := os.ReadFile(filepath.Join(pluginsRoot, "installed_plugins.json")); err == nil &&
		json.Unmarshal(data, &installed) == nil {
		for id, raw := range installed.Plugins {
			if at := strings.LastIndex(id, "@"); at >= 0 {
				registry.marketplaces[strings.ToLower(id[at+1:])] = struct{}{}
			}
			var entries []install
			if json.Unmarshal(raw, &entries) != nil {
				var one install
				if json.Unmarshal(raw, &one) == nil {
					entries = []install{one}
				}
			}
			for _, entry := range entries {
				if entry.InstallPath != "" {
					registry.installPaths = append(registry.installPaths, entry.InstallPath)
				}
			}
		}
	}
	return registry
}

func (r claudePluginRegistry) marketplace(name string) bool {
	_, ok := r.marketplaces[strings.ToLower(name)]
	return ok
}

func (r claudePluginRegistry) installed(path string) bool {
	for _, installPath := range r.installPaths {
		if sameWatcherPath(installPath, path) {
			return true
		}
	}
	return false
}

// claudeCacheParts splits path, when it lies below a plugin root named
// cache, into the root and its folder names relative to it. Both separators
// split, so a Windows path reads the same on every host.
func (w *InstallWatcher) claudeCacheParts(path string) (root string, parts []string, ok bool) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, false
	}
	for _, dir := range w.pluginDirs {
		rootAbs, absErr := filepath.Abs(dir)
		if absErr != nil || !strings.EqualFold(filepath.Base(rootAbs), "cache") {
			continue
		}
		relative, relErr := filepath.Rel(rootAbs, pathAbs)
		if relErr != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		return rootAbs, splitCacheRelative(relative), true
	}
	return "", nil, false
}

// splitCacheRelative splits a path relative to a plugin cache on both
// separators.
func splitCacheRelative(relative string) []string {
	return strings.FieldsFunc(relative, func(r rune) bool { return r == '/' || r == '\\' })
}

// isPluginStagingFolder names the .dclaw-stage-<name>-<random> folder that
// "defenseclaw plugin install" copies a plugin into, scans and decides
// itself before it moves the copy to cache/<name> (GAP-0017).
func isPluginStagingFolder(name string) bool {
	const prefix = ".dclaw-stage-"
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, prefix) && len(lower) > len(prefix)
}
