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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// claudeStagingGrace is how long a plugin install in flight (a Claude
	// Code staging folder, a <version>.linking-<pid> folder) is left alone
	// after its last write.
	claudeStagingGrace = 15 * time.Minute
	// claudeStagingCap bounds how long a folder is an install in flight
	// however recently it was written: a slow clone of a big marketplace is
	// not quarantined mid-clone, and nothing stays unscanned longer. Claude
	// Code's own cache sweep leaves a staging folder for 14 days before it
	// deletes it; the watcher does not wait that long, because what such a
	// folder holds is on disk unscanned: after the cap it is admitted and
	// enforced like any plugin.
	claudeStagingCap = time.Hour
	// claudeStagingSkew is how far ahead of the clock a staging folder's
	// name stamp may be and still be clock skew, as in Claude Code's sweep.
	claudeStagingSkew = 6 * time.Hour
	// claudeStagingRecheck is how often the live watcher looks again at the
	// installs in flight it left alone.
	claudeStagingRecheck = 30 * time.Second
	// claudeStagingRecheckBudget bounds one re-check on the live watcher's
	// event loop, so its events keep draining; what is left waits for the
	// next tick.
	claudeStagingRecheckBudget = 200 * time.Millisecond
	// claudeStagingMemo is how long one answer about a folder (in flight or
	// not) and one read of Claude Code's registry serve every path below it:
	// a rescan or re-check of a clone holding many plugins walks it once.
	claudeStagingMemo = 5 * time.Second
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
	// claudeCacheStaging lies in a staging folder.
	claudeCacheStaging
	// claudeCacheStagingGit lies in the .git folder of a staging clone.
	claudeCacheStagingGit
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

// stagingKey is the map key of a staging path: case folded where the file
// system usually is (Windows, macOS), so one folder has one entry.
func stagingKey(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(path)
	}
	return path
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
// install path. The .git folder of an unregistered staging clone is git's
// own files, which Claude Code never loads: never a plugin, however old.
// What the live watcher leaves alone it looks at again
// (deferClaudeStaging); the rescan hands what outlived the window to the
// same admission (admitsAfterStaging). grace applies to the
// .dclaw-stage-<name>-<random> folder "defenseclaw plugin install" stages
// in, left alone in every cache (GAP-0017) up to the same cap; Codex has no
// other rule. The Secure Client profile keeps the earlier behaviour.
func (w *InstallWatcher) inClaudePluginStaging(path string, grace time.Duration) bool {
	if w.secureClientActive() {
		return false
	}
	root, parts, ok := w.claudeCacheParts(path)
	if !ok {
		return false
	}
	if isPluginStagingFolder(parts[0]) {
		folder := filepath.Join(root, parts[0])
		if !w.withinStagingCap(folder, time.Time{}) {
			return false
		}
		return grace <= 0 || w.modifiedWithin(folder, grace)
	}
	if w.connectorForPath(root) != "claudecode" {
		return false
	}
	switch kind := classifyClaudeCacheParts(parts); kind {
	case claudeCacheStaging, claudeCacheStagingGit:
		folder := filepath.Join(root, parts[0])
		if kind == claudeCacheStaging && !w.claudeInFlight(folder, claudeStagingStamp(parts[0])) {
			return false
		}
		if _, err := os.Lstat(folder); err != nil {
			return false
		}
		registry := w.claudeRegistry(filepath.Dir(root))
		return !registry.marketplace(parts[0]) && !registry.installedAtOrBelow(folder)
	case claudeCacheLinking:
		folder := filepath.Join(root, parts[0], parts[1], parts[2])
		return w.claudeInFlight(folder, time.Time{}) &&
			!w.claudeRegistry(filepath.Dir(root)).installedAtOrBelow(folder)
	}
	return false
}

// withinStagingCap reports a folder first seen (or stamped) less than
// claudeStagingCap ago, and notes when it was first seen.
func (w *InstallWatcher) withinStagingCap(folder string, stamp time.Time) bool {
	now := w.stagingNow()
	key := stagingKey(folder)
	w.stagingMu.Lock()
	if w.stagingSeen == nil {
		w.stagingSeen = map[string]time.Time{}
	}
	first, seen := w.stagingSeen[key]
	if !seen {
		first = now
		w.stagingSeen[key] = now
	}
	w.stagingMu.Unlock()
	if !stamp.IsZero() && stamp.Before(first) {
		first = stamp
	}
	return now.Sub(first) < claudeStagingCap
}

// claudeInFlight reports a folder written (its own and its entries'
// modification times, the stamp in its name) less than claudeStagingGrace
// ago and first seen (or stamped) less than claudeStagingCap ago. One
// answer serves every path below the folder for claudeStagingMemo.
func (w *InstallWatcher) claudeInFlight(folder string, stamp time.Time) bool {
	info, err := os.Lstat(folder)
	if err != nil || !info.IsDir() {
		return false
	}
	now := w.stagingNow()
	if !stamp.IsZero() && stamp.After(now.Add(claudeStagingSkew)) {
		return false
	}
	key := stagingKey(folder)
	w.stagingMu.Lock()
	memo, cached := w.stagingMemo[key]
	w.stagingMu.Unlock()
	if cached && now.Sub(memo.at) >= 0 && now.Sub(memo.at) < claudeStagingMemo {
		return memo.inFlight
	}
	inFlight := w.withinStagingCap(folder, stamp)
	if inFlight {
		last := w.newestModTime(folder, info.ModTime())
		if stamp.After(last) {
			last = stamp
		}
		inFlight = now.Sub(last) < claudeStagingGrace
	}
	w.stagingMu.Lock()
	if w.stagingMemo == nil {
		w.stagingMemo = map[string]stagingAnswer{}
	}
	w.stagingMemo[key] = stagingAnswer{at: now, inFlight: inFlight}
	w.stagingMu.Unlock()
	return inFlight
}

// stagingAnswer is one claudeInFlight answer for a folder.
type stagingAnswer struct {
	at       time.Time
	inFlight bool
}

// newestModTime is the newest modification time of folder and what it
// holds (links not followed), reading stagingWalkLimit entries at most
// (claudeStagingWalkLimit unless a test set it).
func (w *InstallWatcher) newestModTime(folder string, newest time.Time) time.Time {
	w.stagingWalks.Add(1)
	limit := w.stagingWalkLimit
	if limit <= 0 {
		limit = claudeStagingWalkLimit
	}
	seen := 0
	_ = filepath.WalkDir(folder, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if seen++; seen > limit {
			return fs.SkipAll
		}
		if info, infoErr := entry.Info(); infoErr == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return newest
}

// modifiedWithin reports a path last modified less than d ago.
func (w *InstallWatcher) modifiedWithin(path string, d time.Duration) bool {
	info, err := os.Lstat(path)
	return err == nil && w.stagingNow().Sub(info.ModTime()) < d
}

// deferClaudeStaging notes a path the live watcher left alone as an install
// in flight, depth folders below the cache, for recheckClaudeStaging. The
// .git folder of a staging clone is never a plugin, so it is not noted.
func (w *InstallWatcher) deferClaudeStaging(path string, depth int) {
	if _, parts, ok := w.claudeCacheParts(path); ok && classifyClaudeCacheParts(parts) == claudeCacheStagingGit {
		return
	}
	w.stagingMu.Lock()
	defer w.stagingMu.Unlock()
	if w.stagingDeferred == nil {
		w.stagingDeferred = map[string]stagingDeferral{}
	}
	w.stagingDeferred[stagingKey(path)] = stagingDeferral{path: path, depth: depth}
}

// stagingDeferral is a path the live watcher left alone and its cache depth.
type stagingDeferral struct {
	path  string
	depth int
}

// recheckClaudeStaging runs on the live watcher's debounce tick, at most
// every claudeStagingRecheck and for claudeStagingRecheckBudget at most: a
// path deferClaudeStaging noted that is still there and no longer an
// install in flight is handed to admit, as a new plugin or a new
// marketplace or plugin folder would be. A version folder Claude Code keeps
// under a .linking-<pid> name (1.0.0-x.linking-1) or a staging folder it
// never moved was skipped as in flight and never queued again; the next
// rescan only recorded its baseline, so nothing it held was blocked. A path
// gone is forgotten. Nothing runs once the watcher stopped
// (forgetClaudeStaging).
func (w *InstallWatcher) recheckClaudeStaging(admit func(path string, depth int)) {
	now := w.stagingNow()
	w.stagingMu.Lock()
	if len(w.stagingDeferred) == 0 || now.Before(w.stagingNextCheck) {
		w.stagingMu.Unlock()
		return
	}
	w.stagingNextCheck = now.Add(claudeStagingRecheck)
	due := make([]stagingDeferral, 0, len(w.stagingDeferred))
	for _, deferral := range w.stagingDeferred {
		due = append(due, deferral)
	}
	w.stagingMu.Unlock()
	slices.SortFunc(due, func(a, b stagingDeferral) int { return strings.Compare(a.path, b.path) })
	deadline := time.Now().Add(claudeStagingRecheckBudget)
	for i, deferral := range due {
		if i > 0 && time.Now().After(deadline) {
			w.stagingMu.Lock()
			w.stagingNextCheck = time.Time{} // go on at the next tick
			w.stagingMu.Unlock()
			return
		}
		_, err := os.Lstat(deferral.path)
		if err == nil && w.inClaudePluginStaging(deferral.path, 0) {
			continue
		}
		w.stagingMu.Lock()
		delete(w.stagingDeferred, stagingKey(deferral.path))
		w.stagingMu.Unlock()
		if err == nil {
			admit(deferral.path, deferral.depth)
		}
	}
	w.stagingMu.Lock()
	for key, answer := range w.stagingMemo {
		if now.Sub(answer.at) >= claudeStagingMemo {
			delete(w.stagingMemo, key)
		}
	}
	for key := range w.registryMemo {
		if now.Sub(w.registryMemo[key].at) >= claudeStagingMemo {
			delete(w.registryMemo, key)
		}
	}
	w.stagingMu.Unlock()
	w.pruneStagingSeen()
}

// pruneStagingSeen forgets the first-seen times of folders that are gone.
func (w *InstallWatcher) pruneStagingSeen() {
	w.stagingMu.Lock()
	keys := make([]string, 0, len(w.stagingSeen))
	for key := range w.stagingSeen {
		keys = append(keys, key)
	}
	w.stagingMu.Unlock()
	for _, key := range keys {
		if _, err := os.Lstat(key); errors.Is(err, os.ErrNotExist) {
			// A case-folded key of an existing folder reads as gone on a
			// case-sensitive volume; it is noted again on its next look.
			w.stagingMu.Lock()
			delete(w.stagingSeen, key)
			w.stagingMu.Unlock()
		}
	}
}

// forgetClaudeStaging drops the deferred installs when the watcher stops.
func (w *InstallWatcher) forgetClaudeStaging() {
	w.stagingMu.Lock()
	defer w.stagingMu.Unlock()
	w.stagingDeferred = nil
	w.stagingSeen = nil
	w.stagingMemo = nil
	w.registryMemo = nil
	w.stagingNextCheck = time.Time{}
}

// admitClaudeStaging hands a path recheckClaudeStaging found settled to
// install admission: a version folder is queued as a new plugin, a
// marketplace or plugin folder has what it holds queued.
func (w *InstallWatcher) admitClaudeStaging(ctx context.Context, path string, depth int) {
	if copyRoot, copied := w.cachePluginCopyRoot(path); copied {
		w.queueStagingAdmission(ctx, copyRoot)
		return
	}
	if depth >= 3 {
		w.queueStagingAdmission(ctx, path)
		return
	}
	w.queueExistingClaudePlugins(ctx, path, depth)
}

// queueStagingAdmission queues a settled install for the live watcher's
// install admission unless it is queued or being admitted already. The
// re-check and the rescan both hand settled installs here, so one is
// admitted (and alerted on) once; the admission records its baseline, so
// a later rescan does not admit it again.
func (w *InstallWatcher) queueStagingAdmission(ctx context.Context, path string) {
	w.mu.Lock()
	_, queued := w.pending[path]
	if queued || w.inFlight[path] {
		w.mu.Unlock()
		return
	}
	w.pending[path] = time.Now()
	w.mu.Unlock()
	w.recordWatcherEvent(ctx, "create", string(InstallPlugin), "")
	w.state.set(w.classifyEvent(path), AdmissionPending)
}

// admitsAfterStaging reports a plugin without a baseline that must go
// through install admission (scan, verdict, block/quarantine), not a
// baseline scan: one in a Claude Code staging or linking folder, which the
// watcher left alone as an install in flight until it outlived the window.
// Recording a baseline would leave what it holds unenforced.
func (w *InstallWatcher) admitsAfterStaging(evt InstallEvent) bool {
	if evt.Type != InstallPlugin || w.secureClientActive() {
		return false
	}
	root, parts, ok := w.claudeCacheParts(evt.Path)
	return ok && w.connectorForPath(root) == "claudecode" &&
		classifyClaudeCacheParts(parts) != claudeCachePlugin
}

// claudePluginRegistry is what Claude Code registered next to its cache:
// marketplace names (known_marketplaces.json keys and the @marketplace part
// of installed_plugins.json ids, lower-cased) and install paths.
type claudePluginRegistry struct {
	marketplaces map[string]struct{}
	installPaths []string
}

// registryAnswer is one read of Claude Code's registry.
type registryAnswer struct {
	at       time.Time
	registry claudePluginRegistry
}

// claudeRegistry reads Claude Code's registry in pluginsRoot once per
// claudeStagingMemo.
func (w *InstallWatcher) claudeRegistry(pluginsRoot string) claudePluginRegistry {
	now := w.stagingNow()
	key := stagingKey(pluginsRoot)
	w.stagingMu.Lock()
	memo, cached := w.registryMemo[key]
	w.stagingMu.Unlock()
	if cached && now.Sub(memo.at) >= 0 && now.Sub(memo.at) < claudeStagingMemo {
		return memo.registry
	}
	registry := readClaudePluginRegistry(pluginsRoot)
	w.stagingMu.Lock()
	if w.registryMemo == nil {
		w.registryMemo = map[string]registryAnswer{}
	}
	w.registryMemo[key] = registryAnswer{at: now, registry: registry}
	w.stagingMu.Unlock()
	return registry
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

// installedAtOrBelow reports an install path at or below folder. Both
// separators split and case is folded, so a path Claude Code wrote with
// backslashes or another case (Windows, macOS) reads the same.
func (r claudePluginRegistry) installedAtOrBelow(folder string) bool {
	norm := func(path string) string {
		return strings.TrimRight(strings.ToLower(strings.ReplaceAll(path, `\`, "/")), "/")
	}
	base := norm(filepath.Clean(folder))
	for _, installPath := range r.installPaths {
		path := norm(installPath)
		if path == base || strings.HasPrefix(path, base+"/") {
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
