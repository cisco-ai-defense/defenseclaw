// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// claudeStagingGrace is how long a Claude Code plugin install in flight
	// (a staging folder, a <version>.linking-<pid> folder) is left alone
	// after its last write.
	claudeStagingGrace = 15 * time.Minute
	// claudeStagingCap bounds how long a folder is an install in flight
	// however recently it was written: a slow clone of a big marketplace
	// is not quarantined mid-clone, and nothing stays unscanned longer.
	claudeStagingCap = time.Hour
	// claudeStagingRecheck is how often the live watcher looks again at the
	// installs in flight it left alone.
	claudeStagingRecheck = 30 * time.Second
	// claudeStagingWalkLimit bounds the entries read to find a staging
	// folder's newest write.
	claudeStagingWalkLimit = 20000
)

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
// fills before it renames it to <version>. A real version may end so too
// (1.0.0-x.linking-1), so it is in flight only while it is being written.
var claudeLinkingVersion = regexp.MustCompile(`^.+\.linking-\d+$`)

// claudeCacheEntry is what a path below Claude Code's plugin cache is, by
// its folder names alone.
type claudeCacheEntry int

const (
	// claudeCachePlugin is the cache's own <marketplace>/<plugin>/<version>
	// layout: read as plugins.
	claudeCachePlugin claudeCacheEntry = iota
	// claudeCacheStaging lies in a staging folder (its .git included).
	claudeCacheStaging
	// claudeCacheLinking lies in a <version>.linking-<pid> folder.
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
		return claudeCacheStaging
	}
	if len(parts) >= 3 && claudeLinkingVersion.MatchString(parts[2]) {
		return claudeCacheLinking
	}
	return claudeCachePlugin
}

// claudeStagingStamp is the time stamp in a staging folder name, or zero.
func claudeStagingStamp(name string) time.Time {
	match := claudeStagingName.FindStringSubmatch(name)
	if match == nil {
		return time.Time{}
	}
	millis, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMilli(millis)
}

func (w *InstallWatcher) stagingNow() time.Time {
	if w.stagingClock != nil {
		return w.stagingClock()
	}
	return time.Now()
}

// inClaudePluginStaging reports a path in a plugin cache that is a plugin
// install in flight, not a plugin. Claude Code builds a plugin in
// cache/temp_local_<ts>_<r>, clones a marketplace or a git plugin into
// cache/temp_<kind>_<ts>_<r>[.clone] and fills <version>.linking-<pid>
// before it moves the result to <marketplace>/<plugin>/<version>. The
// watcher read those as plugins (".git@temp_subdir_<n>.clone",
// "skills@temp_github_<n>"), found no manifest and quarantined them while
// Claude Code still wrote them, so the install or "claude plugin update"
// failed (GAP-0629, issue #1428). Such a folder is in flight while it was
// written in the last claudeStagingGrace, for claudeStagingCap at most
// (claudeInFlight), and never when Claude Code registered it: a name in
// known_marketplaces.json or installed_plugins.json, or a folder holding an
// install path. What the live watcher leaves alone it looks at again
// (deferClaudeStaging); the rescan admits what outlived the window
// (admitsAfterStaging). grace applies to the .dclaw-stage-<name>-<random>
// folder "defenseclaw plugin install" stages in, left alone in every cache
// (GAP-0017); Codex has no other rule. The Secure Client profile keeps the
// earlier behaviour.
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
	case claudeCacheStaging:
		folder := filepath.Join(root, parts[0])
		if !w.claudeInFlight(folder, claudeStagingStamp(parts[0])) {
			return false
		}
		registry := readClaudePluginRegistry(filepath.Dir(root))
		return !registry.marketplace(parts[0]) && !registry.installedAtOrBelow(folder)
	case claudeCacheLinking:
		folder := filepath.Join(root, parts[0], parts[1], parts[2])
		return w.claudeInFlight(folder, time.Time{}) &&
			!readClaudePluginRegistry(filepath.Dir(root)).installedAtOrBelow(folder)
	}
	return false
}

// claudeInFlight reports a folder written (its own and its entries'
// modification times, the stamp in its name) less than claudeStagingGrace
// ago and first seen (or stamped) less than claudeStagingCap ago.
func (w *InstallWatcher) claudeInFlight(folder string, stamp time.Time) bool {
	info, err := os.Lstat(folder)
	if err != nil || !info.IsDir() {
		return false
	}
	now := w.stagingNow()
	if !stamp.IsZero() && stamp.After(now.Add(time.Minute)) {
		return false
	}
	w.stagingMu.Lock()
	if w.stagingSeen == nil {
		w.stagingSeen = map[string]time.Time{}
	}
	first, seen := w.stagingSeen[folder]
	if !seen {
		first = now
		w.stagingSeen[folder] = now
	}
	w.stagingMu.Unlock()
	if !stamp.IsZero() && stamp.Before(first) {
		first = stamp
	}
	if now.Sub(first) >= claudeStagingCap {
		return false
	}
	last := newestModTime(folder, info.ModTime())
	if stamp.After(last) {
		last = stamp
	}
	return now.Sub(last) < claudeStagingGrace
}

// newestModTime is the newest modification time of folder and what it
// holds (links not followed), reading claudeStagingWalkLimit entries at
// most.
func newestModTime(folder string, newest time.Time) time.Time {
	seen := 0
	_ = filepath.WalkDir(folder, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if seen++; seen > claudeStagingWalkLimit {
			return fs.SkipAll
		}
		if info, infoErr := entry.Info(); infoErr == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return newest
}

// deferClaudeStaging notes a path the live watcher left alone as an install
// in flight, depth folders below the cache, for recheckClaudeStaging.
func (w *InstallWatcher) deferClaudeStaging(path string, depth int) {
	w.stagingMu.Lock()
	defer w.stagingMu.Unlock()
	if w.stagingDeferred == nil {
		w.stagingDeferred = map[string]int{}
	}
	w.stagingDeferred[path] = depth
}

// recheckClaudeStaging runs on the live watcher's debounce tick, at most
// every claudeStagingRecheck: a path deferClaudeStaging noted that is still
// there and no longer an install in flight is handed to admit, as a new
// plugin or a new marketplace or plugin folder would be. A version folder
// Claude Code keeps under a .linking-<pid> name (1.0.0-x.linking-1) or a
// staging folder it never moved was skipped as in flight and never queued
// again; the next rescan only recorded its baseline, so nothing it held
// was blocked. A path gone is forgotten. Nothing runs once the watcher
// stopped (forgetClaudeStaging).
func (w *InstallWatcher) recheckClaudeStaging(admit func(path string, depth int)) {
	now := w.stagingNow()
	w.stagingMu.Lock()
	if len(w.stagingDeferred) == 0 || now.Before(w.stagingNextCheck) {
		w.stagingMu.Unlock()
		return
	}
	w.stagingNextCheck = now.Add(claudeStagingRecheck)
	due := make(map[string]int, len(w.stagingDeferred))
	for path, depth := range w.stagingDeferred {
		due[path] = depth
	}
	w.stagingMu.Unlock()
	for path, depth := range due {
		_, err := os.Lstat(path)
		if err == nil && w.inClaudePluginStaging(path, 0) {
			continue
		}
		w.stagingMu.Lock()
		delete(w.stagingDeferred, path)
		w.stagingMu.Unlock()
		if err == nil {
			admit(path, depth)
		}
	}
	w.stagingMu.Lock()
	for folder := range w.stagingSeen {
		if _, statErr := os.Lstat(folder); errors.Is(statErr, os.ErrNotExist) {
			delete(w.stagingSeen, folder)
		}
	}
	w.stagingMu.Unlock()
}

// forgetClaudeStaging drops the deferred installs when the watcher stops.
func (w *InstallWatcher) forgetClaudeStaging() {
	w.stagingMu.Lock()
	defer w.stagingMu.Unlock()
	w.stagingDeferred = nil
	w.stagingSeen = nil
	w.stagingNextCheck = time.Time{}
}

// admitClaudeStaging hands a path recheckClaudeStaging found settled to
// install admission: a version folder is queued as a new plugin, a
// marketplace or plugin folder has what it holds queued.
func (w *InstallWatcher) admitClaudeStaging(ctx context.Context, path string, depth int) {
	if copyRoot, copied := w.cachePluginCopyRoot(path); copied {
		w.recordWatcherEvent(ctx, "create", string(InstallPlugin), "")
		w.queuePending(copyRoot)
		return
	}
	if depth >= 3 {
		w.recordWatcherEvent(ctx, "create", string(InstallPlugin), "")
		w.queuePending(path)
		return
	}
	w.queueExistingClaudePlugins(ctx, path, depth)
}

// admitsAfterStaging reports a plugin without a baseline that the rescan
// must admit (scan, verdict, block/quarantine) rather than baseline: one in
// a Claude Code staging or linking folder, which the watcher left alone as
// an install in flight until it outlived the window. Recording a baseline
// would leave what it holds unenforced.
func (w *InstallWatcher) admitsAfterStaging(evt InstallEvent) bool {
	if evt.Type != InstallPlugin || w.secureClientActive() {
		return false
	}
	root, parts, ok := w.claudeCacheParts(evt.Path)
	return ok && w.connectorForPath(root) == "claudecode" &&
		classifyClaudeCacheParts(parts) != claudeCachePlugin
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

// installedAtOrBelow reports an install path at or below folder.
func (r claudePluginRegistry) installedAtOrBelow(folder string) bool {
	for _, installPath := range r.installPaths {
		if watcherPathAtOrBelow(installPath, folder) {
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
