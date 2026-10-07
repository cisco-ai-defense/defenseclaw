// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hermesskills"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// DriftType classifies the kind of change detected between re-scans.
type DriftType string

const (
	DriftNewFinding       DriftType = "new_finding"
	DriftRemovedFinding   DriftType = "resolved_finding"
	DriftSeverityChange   DriftType = "severity_escalation"
	DriftContentChange    DriftType = "content_change"
	DriftDependencyChange DriftType = "dependency_change"
	DriftConfigMutation   DriftType = "config_mutation"
	DriftNewEndpoint      DriftType = "new_endpoint"
	DriftRemovedEndpoint  DriftType = "removed_endpoint"
)

// DriftDelta represents a single detected change between baseline and current state.
type DriftDelta struct {
	Type        DriftType `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Previous    string    `json:"previous,omitempty"`
	Current     string    `json:"current,omitempty"`
	// RuleID is the underlying detection rule that triggered this
	// drift delta. Populated for finding-driven deltas
	// (new_finding, resolved_finding, severity_escalation on a
	// specific finding) so SIEM queries can join drift events back
	// to the scan_findings rows they reference. Empty for content /
	// dependency / endpoint deltas that don't map to a single rule.
	RuleID string `json:"rule_id,omitempty"`
}

// rescanLoop runs periodic re-scans of all installed skills, plugins, and MCPs,
// compares against baseline snapshots, and emits drift alerts.
func (w *InstallWatcher) rescanLoop(ctx context.Context) {
	interval := time.Duration(w.cfg.Watch.RescanIntervalMin) * time.Minute
	if interval <= 0 {
		interval = 60 * time.Minute
	}

	fmt.Fprintf(os.Stderr, "[rescan] periodic re-scan enabled (interval=%s)\n", interval)
	_ = w.logger.LogAction(string(audit.ActionRescanStart), "", fmt.Sprintf("interval=%s", interval))

	// Bootstrap a baseline immediately so already-installed targets are not
	// blind for the first full interval after startup.
	w.runRescanCycle(ctx)

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			w.runRescanCycle(ctx)
			timer.Reset(interval)
		case <-w.rescanNow:
			w.runRescanCycle(ctx)
		}
	}
}

// rescanOutcome reports whether a single target was actually scanned during a
// rescan cycle or skipped because nothing relevant changed.
type rescanOutcome int

const (
	rescanSkipped rescanOutcome = iota
	rescanScanned
)

// runRescanCycle enumerates all installed targets and re-scans each one.
//
// The scanner is expensive (subprocess + optional LLM/network calls), so a
// target is only scanned when its content or the scanner fingerprint changed
// since the last baseline. Unchanged targets are skipped entirely, which keeps
// the periodic loop cheap and stops scan_results from growing on every cycle.
func (w *InstallWatcher) runRescanCycle(ctx context.Context) {
	defer func() { w.startupRescanDone = true }()
	if !w.startupRescanDone {
		w.startupAdmitRoots = w.baselinedWatchRoots()
		defer func() { w.startupAdmitRoots = nil }()
	}
	targets := w.enumerateTargets()
	if len(targets) == 0 {
		w.markWatchRoots()
		return
	}

	fmt.Fprintf(os.Stderr, "[rescan] starting periodic re-scan of %d targets\n", len(targets))

	// Scanner fingerprints depend on the target *type*, not the individual
	// target, so compute them at most once per kind per cycle.
	fpCache := make(map[string]string)

	var scanned, skipped int
	for _, evt := range targets {
		if ctx.Err() != nil {
			return
		}
		outcome := w.rescanTarget(ctx, evt, fpCache)
		if outcome == rescanScanned {
			scanned++
			w.recordWatcherEvent(ctx, "rescan_scan", string(evt.Type), "")
		} else {
			skipped++
			w.recordWatcherEvent(ctx, "rescan_skip", string(evt.Type), "")
		}
	}
	w.markWatchRoots()

	fmt.Fprintf(os.Stderr, "[rescan] cycle complete: targets=%d scanned=%d skipped=%d\n",
		len(targets), scanned, skipped)
	_ = w.logger.LogAction(string(audit.ActionRescan), "",
		fmt.Sprintf("targets=%d scanned=%d skipped=%d", len(targets), scanned, skipped))
}

// watchRootMarkerType is the target_snapshots type of the marker row saying
// a skill or plugin root was covered by a completed rescan cycle.
func watchRootMarkerType(typ InstallType) string { return string(typ) + "_root" }

// baselinedWatchRoots lists, per type, the skill and plugin roots that a
// completed rescan cycle covered in an earlier run: a root with a marker row,
// or one holding baselines from a build without markers. A target without a
// baseline under one of them arrived while the gateway was stopped (GAP-2475),
// even when the root was empty before. On a first start nothing is listed, so
// the startup rescan only records baselines, as before.
func (w *InstallWatcher) baselinedWatchRoots() map[InstallType][]string {
	roots := make(map[InstallType][]string)
	for typ, dirs := range map[InstallType][]string{InstallSkill: w.skillDirs, InstallPlugin: w.pluginDirs} {
		if len(dirs) == 0 {
			continue
		}
		paths, err := w.store.ListTargetSnapshotPaths(string(typ))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rescan] list %s baselines: %v\n", typ, err)
			continue
		}
		markers, err := w.store.ListTargetSnapshotPaths(watchRootMarkerType(typ))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rescan] list %s root markers: %v\n", typ, err)
		}
		paths = append(paths, markers...)
		for _, dir := range dirs {
			for _, path := range paths {
				if watcherPathAtOrBelow(path, dir) {
					roots[typ] = append(roots[typ], dir)
					break
				}
			}
		}
	}
	return roots
}

// markWatchRoots records, after a completed rescan cycle, that every existing
// skill and plugin root was covered, so a target added to it while the gateway
// is stopped is admitted at the next start even if the root was empty.
func (w *InstallWatcher) markWatchRoots() {
	if w.markedWatchRoots == nil {
		w.markedWatchRoots = make(map[string]bool)
	}
	for typ, dirs := range map[InstallType][]string{InstallSkill: w.skillDirs, InstallPlugin: w.pluginDirs} {
		markerType := watchRootMarkerType(typ)
		for _, dir := range dirs {
			key := markerType + "\x00" + dir
			if w.markedWatchRoots[key] {
				continue
			}
			if _, err := os.Lstat(dir); err != nil {
				continue
			}
			if err := w.store.SetTargetSnapshot(markerType, dir, "", "{}", "{}", "[]", "", ""); err != nil {
				fmt.Fprintf(os.Stderr, "[rescan] mark %s root %s: %v\n", typ, dir, err)
				continue
			}
			w.markedWatchRoots[key] = true
		}
	}
}

// admitsAtStartup reports whether the startup rescan must run install
// admission for evt, a skill or plugin without a baseline under a root that
// was baselined before.
func (w *InstallWatcher) admitsAtStartup(evt InstallEvent) bool {
	for _, root := range w.startupAdmitRoots[evt.Type] {
		if watcherPathAtOrBelow(evt.Path, root) {
			return true
		}
	}
	return false
}

// hermesSkillsDiscover returns how to list dir's Hermes skills, or nil when
// dir is not a Hermes skills root: this process's own root, or a user
// profile's root that the managed gateway watches for every enrolled user.
// IsRoot alone resolves only the service account's own Hermes home, so each
// user's category folders (devops, software-development) were rescanned as
// skills and logged a failed scan every cycle (GAP-0285). trustBundled is
// false for a profile root: its manifest and Hermes checkout belong to that
// account, which could mark its own skill bundled, so every skill there is
// rescanned.
func hermesSkillsDiscover(dir string) (discover func(string, int) ([]hermesskills.Entry, error), trustBundled bool) {
	switch {
	case hermesskills.IsRoot(dir):
		return hermesskills.Discover, true
	case hermesskills.IsProfileRoot(dir):
		return hermesskills.DiscoverProfileRoot, false
	}
	return nil, false
}

// enumerateTargets lists all direct child directories under watched roots plus
// configured MCP servers from openclaw.json.
func (w *InstallWatcher) enumerateTargets() []InstallEvent {
	var targets []InstallEvent

	for _, dir := range w.skillDirs {
		// A watch folder the agent has not created yet is deferred by the
		// watcher; there is nothing in it to rescan (GAP-2384).
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if discover, trustBundled := hermesSkillsDiscover(dir); discover != nil {
			entries, err := discover(dir, hermesskills.DefaultDirectoryLimit)
			if err == nil {
				for _, entry := range entries {
					if entry.Bundled && trustBundled {
						continue
					}
					targets = append(targets, InstallEvent{
						Type:      InstallSkill,
						Name:      entry.Name,
						Path:      entry.Path,
						Connector: "hermes",
						Timestamp: time.Now().UTC(),
					})
				}
				continue
			}
			// Discovery errors deliberately fall through to the ordinary
			// direct-child scan. Failure to prove vendor provenance must not
			// turn an untrusted category tree into a scanner bypass.
			fmt.Fprintf(os.Stderr, "[rescan] enumerate Hermes skills dir %s: %v\n", dir, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rescan] enumerate skills dir %s: %v\n", dir, err)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if isBundledSkillWatchPath(path) {
				continue
			}
			if synced, ok := claudeSyncedSkillDirs(path); ok {
				for _, skill := range synced {
					targets = append(targets, InstallEvent{
						Type:      InstallSkill,
						Name:      filepath.Base(skill),
						Path:      skill,
						Timestamp: time.Now().UTC(),
					})
				}
				continue
			}
			if w.connectorForPath(path) == "claudecode" &&
				isClaudeSkillsPlugin(path) {
				continue
			}
			targets = append(targets, InstallEvent{
				Type:      InstallSkill,
				Name:      e.Name(),
				Path:      path,
				Timestamp: time.Now().UTC(),
			})
		}
	}

	for _, dir := range w.pluginDirs {
		if w.connectorForPath(dir) == "claudecode" {
			for _, plugin := range enumerateClaudeWatcherPlugins(dir) {
				if w.isOwnPlugin(plugin) {
					continue
				}
				targets = append(targets, InstallEvent{
					Type:      InstallPlugin,
					Name:      claudeWatcherPluginIdentity(dir, plugin),
					Path:      plugin,
					Connector: "claudecode",
					Timestamp: time.Now().UTC(),
				})
			}
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Deferred until the agent creates it, as for skills above.
			if !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "[rescan] enumerate plugins dir %s: %v\n", dir, err)
			}
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || skipPluginChildDir(e.Name()) {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if w.isOwnPlugin(path) {
				continue
			}
			// A folder of plugins (Hermes hermes-agent/plugins/browser,
			// memory, platforms, ...) is not a plugin: the plugin scanner
			// refuses it (GAP-1580). Rescan the plugins inside it instead,
			// keyed by the category/name id 'plugin list' shows (GAP-2411).
			if children := pluginFolderChildren(path); len(children) > 0 {
				bare := w.hermesBareCategory(dir, e.Name())
				for _, child := range children {
					childPath := filepath.Join(path, child)
					if w.isOwnPlugin(childPath) {
						continue
					}
					name := e.Name() + "/" + child
					if bare {
						name = child
					}
					targets = append(targets, InstallEvent{
						Type:      InstallPlugin,
						Name:      name,
						Path:      childPath,
						Timestamp: time.Now().UTC(),
					})
				}
				continue
			}
			if w.hermesCategoryFolder(path) {
				continue // a Hermes category folder with no plugins yet (GAP-2471)
			}
			targets = append(targets, InstallEvent{
				Type:      InstallPlugin,
				Name:      e.Name(),
				Path:      path,
				Timestamp: time.Now().UTC(),
			})
		}
	}

	servers, err := w.readMCPServers()
	if err != nil {
		// No agent config yet means no MCP servers to rescan.
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "[rescan] enumerate mcp servers: %v\n", err)
		}
		return targets
	}
	for _, server := range servers {
		if strings.TrimSpace(server.Name) == "" || server.Bundled {
			continue
		}
		targets = append(targets, InstallEvent{
			Type:      InstallMCP,
			Name:      server.Name,
			Path:      MCPEventPath(server),
			Connector: server.Connector,
			Timestamp: time.Now().UTC(),
		})
	}

	return targets
}

// skipPluginChildDir reports whether a child of a plugin root is not a
// plugin: a dot-dir, a Python bytecode cache or an npm dependency tree.
// Hermes' plugins folder is a Python package, so it holds __pycache__; the
// CLI inventory skips these too (GAP-1086), while the gateway scanned it and
// raised a MANIFEST-MISSING finding on every start (GAP-2338).
// hermesBareCategory reports whether the plugins in the category folder of
// plugin root dir go by their bare folder name. Hermes lists its bundled
// platforms/* plugins (hermes-agent/plugins/platforms/a2a) as "a2a": that is
// the id "plugin list" shows and "plugin scan" accepts, so the rescan log
// names them the same way (GAP-2439). The user plugin root (~/.hermes/plugins)
// keeps category/name, as "plugin list" does.
func (w *InstallWatcher) hermesBareCategory(dir, category string) bool {
	if category != "platforms" || w.connectorForPath(dir) != "hermes" {
		return false
	}
	dir = filepath.Clean(dir)
	if filepath.Base(dir) == "plugins" && filepath.Base(filepath.Dir(dir)) == "hermes-agent" {
		return true
	}
	bundled := strings.TrimSpace(os.Getenv("HERMES_BUNDLED_PLUGINS"))
	return bundled != "" && filepath.Clean(bundled) == dir
}

func skipPluginChildDir(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch strings.ToLower(name) {
	case "__pycache__", "node_modules":
		return true
	}
	return false
}

// pluginManifestNames mirrors the plugin scanner's manifest candidates
// (cli/defenseclaw/scanner/plugin_scanner/scanner.py _MANIFEST_CANDIDATES).
var pluginManifestNames = []string{
	"package.json",
	"manifest.json",
	"plugin.json",
	"openclaw.plugin.json",
	filepath.Join(".claude-plugin", "plugin.json"),
	filepath.Join(".codex-plugin", "plugin.json"),
	filepath.Join(".cursor-plugin", "plugin.json"),
	"plugin.yaml",
	"plugin.yml",
}

func hasPluginManifest(path string) bool {
	for _, name := range pluginManifestNames {
		if info, err := os.Stat(filepath.Join(path, name)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// pluginFolderChildren returns the sub-folders of path that hold a plugin
// manifest when path itself has none: the same test the CLI plugin scanner
// uses to refuse a folder of plugins (cmd_plugin._plugin_folder_children).
func pluginFolderChildren(path string) []string {
	if hasPluginManifest(path) {
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			continue
		}
		if hasPluginManifest(filepath.Join(path, name)) {
			out = append(out, name)
		}
	}
	return out
}

func isClaudeSkillsPlugin(path string) bool {
	info, err := os.Lstat(filepath.Join(path, ".claude-plugin", "plugin.json"))
	return err == nil && info.Mode().IsRegular()
}

func claudeSkillsPluginIdentity(path string) string {
	fallback := filepath.Base(path) + "@skills-dir"
	manifestPath := filepath.Join(path, ".claude-plugin", "plugin.json")
	info, err := os.Lstat(manifestPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1_048_576 {
		return fallback
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fallback
	}
	var manifest struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return fallback
	}
	name := strings.TrimSpace(manifest.Name)
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return fallback
	}
	return name + "@skills-dir"
}

func claudeWatcherPluginIdentity(root, path string) string {
	root = filepath.Clean(root)
	if strings.EqualFold(filepath.Base(root), "skills") {
		return claudeSkillsPluginIdentity(path)
	}
	if strings.EqualFold(filepath.Base(root), "cache") {
		relative, err := filepath.Rel(root, path)
		if err == nil {
			parts := strings.FieldsFunc(relative, func(r rune) bool {
				return r == '/' || r == '\\'
			})
			if len(parts) == 3 {
				return parts[1] + "@" + parts[0]
			}
		}
	}
	return filepath.Base(path)
}

func enumerateClaudeWatcherPlugins(root string) []string {
	root = filepath.Clean(root)
	if strings.EqualFold(filepath.Base(root), "skills") {
		var out []string
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil
		}
		for _, entry := range entries {
			path := filepath.Join(root, entry.Name())
			if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") &&
				isClaudeSkillsPlugin(path) {
				out = append(out, path)
			}
		}
		return out
	}
	if !strings.EqualFold(filepath.Base(root), "cache") {
		return nil
	}

	var out []string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return filepath.SkipAll
			}
			return filepath.SkipDir
		}
		if !entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return filepath.SkipDir
		}
		depth := 0
		if relative != "." {
			depth = len(strings.FieldsFunc(relative, func(r rune) bool {
				return r == '/' || r == '\\'
			}))
		}
		if depth > 3 {
			return filepath.SkipDir
		}
		// Anthropic's cache boundary is
		// <marketplace>/<plugin>/<version>; plugin.json is optional. Admit
		// exactly that directory and never let a nested dependency manifest
		// manufacture a second plugin identity.
		if depth == 3 {
			out = append(out, path)
			return filepath.SkipDir
		}
		if entry.Name() != "." && strings.HasPrefix(entry.Name(), ".") {
			return filepath.SkipDir
		}
		switch strings.ToLower(entry.Name()) {
		case "node_modules", "__pycache__":
			return filepath.SkipDir
		}
		return nil
	})
	return out
}

// rescanTarget snapshots a single target, decides whether a fresh scan is
// warranted (content drift or scanner-fingerprint change), and only then runs
// the scanner, diffs findings, emits drift alerts, and refreshes the baseline.
// Targets whose content and scanner fingerprint are unchanged are skipped
// without invoking the scanner or writing a scan_results row.
func (w *InstallWatcher) rescanTarget(ctx context.Context, evt InstallEvent, fpCache map[string]string) rescanOutcome {
	if evt.Type == InstallMCP {
		w.mcpMu.Lock()
		defer w.mcpMu.Unlock()
	}
	if evt.Type == InstallSkill && isBundledSkillWatchPath(evt.Path) {
		return rescanSkipped
	}
	if evt.Type == InstallPlugin {
		// Re-check here: the connector may have restored its own plugin
		// since enumerateTargets ran (GAP-1525).
		if w.isOwnPlugin(evt.Path) {
			return rescanSkipped
		}
		// At gateway start the connector's Setup rewrites its own plugin
		// dir, so an old (upgrade) or drifted copy there is about to be
		// replaced by the bundled one. Leave it to admission, which sees
		// the rewrite, and to the next cycle, which scans it if it still
		// differs.
		if !w.startupRescanDone && w.isBundledPluginDir(evt.Path) {
			fmt.Fprintf(os.Stderr, "[rescan] deferring %s: connector setup refreshes DefenseClaw's own plugin at start\n", evt.Path)
			return rescanSkipped
		}
	}
	currentSnap, err := w.snapshotForEvent(evt)
	if errors.Is(err, os.ErrNotExist) {
		return rescanSkipped
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] snapshot %s: %v\n", evt.Path, err)
		return rescanSkipped
	}

	fingerprint := w.cachedFingerprint(evt, fpCache)

	baseline, err := w.store.GetTargetSnapshot(string(evt.Type), evt.Path)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if evt.Type == InstallMCP && w.admitNewMCP && w.startupRescanDone {
				// A server added to an enrolled user's agent after the
				// watcher started: admit it as `mcp set` would (GAP-0132).
				fmt.Fprintf(os.Stderr, "[rescan] mcp %s is new; running install admission\n", evt.Name)
				res := w.runAdmission(ctx, evt)
				if w.onAdmit != nil {
					w.onAdmit(res)
				}
				if !res.Interrupted {
					w.persistSnapshot(evt, currentSnap, res.ScanID, fingerprint)
				}
				return rescanScanned
			}
			if w.admitsAtStartup(evt) {
				// Added while the gateway was stopped: admit it as the live
				// watcher would (scan, verdict, block/quarantine; GAP-2475).
				fmt.Fprintf(os.Stderr, "[rescan] %s %s is new since the last run; running install admission\n", evt.Type, evt.Name)
				res := w.runAdmission(ctx, evt)
				if w.onAdmit != nil {
					w.onAdmit(res)
				}
				if _, statErr := os.Lstat(evt.Path); statErr == nil && !res.Interrupted {
					// The admission scan is the baseline scan, so the next
					// start skips the unchanged target (GAP-2507).
					w.persistSnapshot(evt, currentSnap, res.ScanID, fingerprint)
				}
				return rescanScanned
			}
			// First time we've seen this target: scan once to establish a
			// baseline that future cycles can diff against.
			result, scanID := w.scanAndEmit(ctx, evt)
			w.persistSnapshot(evt, currentSnap, scanID, fingerprint)
			if result == nil {
				return rescanSkipped
			}
			return rescanScanned
		}
		fmt.Fprintf(os.Stderr, "[rescan] get baseline %s: %v\n", evt.Path, err)
		return rescanSkipped
	}

	// Cheap content/dependency/config/endpoint drift derived purely from
	// hashes — no scanner subprocess involved.
	deltas := compareSnapshots(baseline, currentSnap)

	scan, reason := shouldRescan(baseline, currentSnap, fingerprint, w.cfg.Watch.RescanContentGated)
	if !scan {
		// Nothing changed and the scanner fingerprint matches: skip the
		// expensive scan entirely. compareSnapshots derives from the same
		// content hash, so deltas is empty here, but emit defensively in
		// case a future cheap signal lands without a content-hash change.
		if len(deltas) > 0 {
			w.emitDriftAlerts(evt, deltas)
			w.persistSnapshot(evt, currentSnap, baseline.ScanID, baseline.ScannerFingerprint)
		}
		return rescanSkipped
	}

	fmt.Fprintf(os.Stderr, "[rescan] scanning %s %s (%s)\n", evt.Type, evt.Name, reason)

	// Drift, fingerprint change, or recovery: run the scanner exactly once
	// and diff its findings against the previous baseline scan.
	result, scanID := w.scanAndEmit(ctx, evt)
	deltas = append(deltas, w.findingDrift(baseline, result)...)

	if len(deltas) > 0 {
		w.emitDriftAlerts(evt, deltas)
	}

	// Avarice F-3188: refuse to overwrite a previously-scanned baseline
	// with an empty scan id. scanAndEmit returns scanID="" when the
	// scanner is unavailable or crashes; persisting that would rewrite
	// the trusted baseline to point at the (mutated, unscanned) current
	// content, and the next cycle would treat the mutation as the
	// trusted baseline. Leaving the prior baseline in place means the
	// content hash still differs next cycle, so a recovered scanner
	// retries and upgrades the baseline. When there is no prior scan id
	// (first-time/recovery baseline) there is no trust state to lose, so
	// we fall through and persist.
	if scanID == "" && baseline.ScanID != "" {
		fmt.Fprintf(os.Stderr,
			"[rescan] refusing to overwrite baseline for %s without scanner evidence (F-3188)\n",
			evt.Path)
		return rescanScanned
	}
	w.persistSnapshot(evt, currentSnap, scanID, fingerprint)
	return rescanScanned
}

// shouldRescan decides whether a target with an existing baseline needs a fresh
// scan. It is a pure function of the baseline, the current snapshot, the
// scanner fingerprint, and whether content-gating is enabled, so it can be unit
// tested without a scanner or store. The returned reason is logged/metric-able.
func shouldRescan(baseline *audit.SnapshotRow, snap *TargetSnapshot, fingerprint string, gated bool) (bool, string) {
	if !gated {
		return true, "gating-disabled"
	}
	if baseline == nil {
		return true, "no-baseline"
	}
	// A baseline that never recorded a scan can't support finding-level drift
	// detection; scan so it can recover.
	if baseline.ScanID == "" {
		return true, "no-baseline-scan"
	}
	if baseline.ContentHash == "" || baseline.ContentHash != snap.ContentHash {
		return true, "content-changed"
	}
	if baseline.ScannerFingerprint != fingerprint {
		return true, "scanner-fingerprint-changed"
	}
	return false, "unchanged"
}

// scanAndEmit runs the scanner for evt once and fans the result through the
// unified emission pipeline (one scan_results row + per-finding rows + events).
// Returns the result and the generated scan ID, or (nil, "") when no scanner is
// configured or the scan fails.
func (w *InstallWatcher) scanAndEmit(ctx context.Context, evt InstallEvent) (*scanner.ScanResult, string) {
	s := w.newScanner(evt)
	if s == nil {
		return nil, ""
	}

	scanCtx, cancel := context.WithTimeout(ctx, w.scanTimeout(evt))
	defer cancel()

	result, err := s.Scan(scanCtx, w.scanTargetFor(evt))
	if err == nil && !w.secureClientActive() {
		// A scan without its judge is incomplete: it never becomes the
		// baseline, so the next cycle scans again (GAP-0376).
		err = scanner.JudgeFailure(result)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] scan %s: %v\n", evt.Path, err)
		return nil, ""
	}
	if result == nil {
		return nil, ""
	}
	return result, w.emitRescanResult(scanCtx, result)
}

// admissionSnapshot hashes a live-watcher target before admission scans it,
// so the baseline describes the content that was scanned. It returns nil
// when periodic rescan is off or the target can't be snapshotted.
func (w *InstallWatcher) admissionSnapshot(evt InstallEvent) *TargetSnapshot {
	if w.store == nil || !w.cfg.Watch.RescanEnabled ||
		(evt.Type != InstallSkill && evt.Type != InstallPlugin) {
		return nil
	}
	snap, err := w.snapshotForEvent(evt)
	if err != nil {
		return nil
	}
	return snap
}

// recordAdmissionBaseline writes the rescan baseline for a target the live
// watcher admitted with a logged scan. Without it the next gateway start
// re-admitted the unchanged target as new, and the start after that scanned
// it again for lack of a baseline scan: three scans and three scan-finding
// alerts for one install (GAP-2507). A target admission moved away gets no
// baseline.
func (w *InstallWatcher) recordAdmissionBaseline(evt InstallEvent, snap *TargetSnapshot, scanID string) {
	if snap == nil || scanID == "" {
		return
	}
	if _, err := os.Lstat(evt.Path); err != nil {
		return
	}
	w.persistSnapshot(evt, snap, scanID, w.scannerFingerprint(evt))
}

// persistSnapshot upserts the baseline snapshot (content/dep/config/endpoint
// hashes plus the scan ID and scanner fingerprint) without running a scan.
func (w *InstallWatcher) persistSnapshot(evt InstallEvent, snap *TargetSnapshot, scanID, fingerprint string) {
	depJSON, _ := json.Marshal(snap.DependencyHashes)
	cfgJSON, _ := json.Marshal(snap.ConfigHashes)
	epJSON, _ := json.Marshal(snap.NetworkEndpoints)

	_ = w.store.SetTargetSnapshot(
		string(evt.Type), evt.Path, snap.ContentHash,
		string(depJSON), string(cfgJSON), string(epJSON), scanID, fingerprint,
	)
}

// findingDrift diffs a freshly scanned result against the baseline's previously
// stored scan, returning finding-level and severity-escalation deltas. It does
// NOT run the scanner — the caller passes the already-computed current result.
func (w *InstallWatcher) findingDrift(baseline *audit.SnapshotRow, current *scanner.ScanResult) []DriftDelta {
	if baseline == nil || baseline.ScanID == "" || current == nil {
		return nil
	}

	prevScan, err := w.loadScanResult(baseline.ScanID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] findingDrift: load baseline scan %s: %v\n", baseline.ScanID, err)
		return nil
	}
	if prevScan == nil {
		return nil
	}

	deltas := diffFindings(prevScan.Findings, current.Findings)

	prevMax := string(prevScan.MaxSeverity())
	curMax := string(current.MaxSeverity())
	if audit.SeverityRank(curMax) > audit.SeverityRank(prevMax) {
		deltas = append(deltas, DriftDelta{
			Type:        DriftSeverityChange,
			Severity:    curMax,
			Description: fmt.Sprintf("max severity escalated from %s to %s", prevMax, curMax),
			Previous:    prevMax,
			Current:     curMax,
		})
	}

	return deltas
}

// cachedFingerprint returns the scanner fingerprint for evt's type, computing
// it (and caching) on first use within a cycle. The fingerprint depends only on
// the scanner kind + config + binary version, not the individual target.
func (w *InstallWatcher) cachedFingerprint(evt InstallEvent, cache map[string]string) string {
	// A skill's fingerprint includes its connector's rule pack.
	key := string(evt.Type)
	if evt.Type == InstallSkill {
		key += "\x00" + w.eventConnector(evt)
	}
	if cache != nil {
		if fp, ok := cache[key]; ok {
			return fp
		}
	}
	fp := w.scannerFingerprint(evt)
	if cache != nil {
		cache[key] = fp
	}
	return fp
}

// scannerFingerprint builds a stable hash over the inputs that determine a
// scanner's output for a given target kind: the scanner binary (path + probed
// version), the scan-affecting settings (policy, judge model, analyzers), the
// connector's rule pack for a skill, and the DefenseClaw build. When any of
// these change, byte-identical targets are re-scanned so updated rules take
// effect. The whole-config hash and the reload generation are not inputs:
// they changed on every config reload and gateway start, so an unrelated key
// (watch.rescan_interval_min) re-ran the paid judge on every installed skill
// (GAP-0415).
//
// Secrets (API keys) are deliberately excluded — only non-sensitive routing
// fields (model, provider, base URL) feed the fingerprint.
func (w *InstallWatcher) scannerFingerprint(evt InstallEvent) string {
	parts := []string{"kind=" + string(evt.Type)}

	switch evt.Type {
	case InstallSkill:
		c := w.cfg.Scanners.SkillScanner
		llm := w.cfg.ResolveLLM("scanners.skill")
		parts = append(parts,
			"binary="+c.Binary,
			"binver="+w.scannerBinaryVersion(c.Binary),
			fmt.Sprintf("use_llm=%t", c.UseLLM),
			fmt.Sprintf("use_behavioral=%t", c.UseBehavioral),
			fmt.Sprintf("enable_meta=%t", c.EnableMeta),
			fmt.Sprintf("use_trigger=%t", c.UseTrigger),
			fmt.Sprintf("use_virustotal=%t", c.Analyzers.VirusTotal.Enabled),
			fmt.Sprintf("use_aidefense=%t", c.Analyzers.AIDefense.Enabled),
			fmt.Sprintf("use_osv=%t", c.Analyzers.OSV.Enabled),
			fmt.Sprintf("llm_consensus=%d", c.LLMConsensus),
			"policy="+c.EffectivePolicy(),
			"policy_digest="+c.PolicyFile.Digest,
			fmt.Sprintf("lenient=%t", c.Lenient),
			"llm_model="+llm.Model,
			"llm_provider="+llm.Provider,
			"llm_base_url="+llm.BaseURL,
			"rulepack="+w.rulePackDigest(evt),
		)
	case InstallMCP:
		c := w.cfg.Scanners.MCPScanner
		llm := w.cfg.ResolveLLM("scanners.mcp")
		parts = append(parts,
			"binary="+c.Binary,
			"binver="+w.scannerBinaryVersion(c.Binary),
			"analyzers="+c.AnalyzersArg(),
			fmt.Sprintf("scan_prompts=%t", c.ScanPrompts),
			fmt.Sprintf("scan_resources=%t", c.ScanResources),
			fmt.Sprintf("scan_instructions=%t", c.ScanInstructions),
			"llm_model="+llm.Model,
			"llm_provider="+llm.Provider,
			"llm_base_url="+llm.BaseURL,
		)
	case InstallPlugin:
		bin := scanner.NewPluginScanner(w.cfg.Scanners.PluginScanner).BinaryPath
		llm := w.cfg.ResolveLLM("scanners.plugin")
		parts = append(parts,
			"binary="+bin,
			"binver="+w.scannerBinaryVersion(bin),
			"llm_model="+llm.Model,
			"llm_provider="+llm.Provider,
			"llm_base_url="+llm.BaseURL,
		)
	}

	prov := version.Current()
	parts = append(parts,
		"prov_binary="+prov.BinaryVersion,
		fmt.Sprintf("prov_schema=%d", prov.SchemaVersion),
	)

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// scannerBinaryVersion best-effort probes `<binary> --version` so the
// fingerprint changes when the (external) scanner is upgraded independently of
// DefenseClaw. Failures (missing binary, no --version support, timeout) are
// non-fatal and yield "" so the rest of the fingerprint still applies.
func (w *InstallWatcher) scannerBinaryVersion(binary string) string {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return ""
	}
	// One probe per binary for the watcher's life (a config change starts a
	// new watcher): it was a Python start per admission and per cycle.
	if cached, ok := w.binaryVersions.Load(binary); ok {
		return cached.(string)
	}
	probed := w.probeScannerBinaryVersion(binary)
	w.binaryVersions.Store(binary, probed)
	return probed
}

// rulePackDigest is the files digest of the rule pack evt's connector adds
// to a skill scan, or "" when none applies.
func (w *InstallWatcher) rulePackDigest(evt InstallEvent) string {
	if w.rulePackSource == nil {
		return ""
	}
	if pack := w.rulePackSource(w.eventConnector(evt)); pack != nil {
		return pack.FilesDigest()
	}
	return ""
}

func (w *InstallWatcher) probeScannerBinaryVersion(binary string) string {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := processutil.CommandContext(ctx, binary, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// loadScanResult retrieves a past scan result from the audit store.
func (w *InstallWatcher) loadScanResult(scanID string) (*scanner.ScanResult, error) {
	rawJSON, err := w.store.GetScanRawJSON(scanID)
	if err != nil {
		return nil, err
	}
	var result scanner.ScanResult
	if err := json.Unmarshal([]byte(rawJSON), &result); err != nil {
		return nil, fmt.Errorf("parse scan result: %w", err)
	}
	return &result, nil
}

// compareSnapshots diffs dependency hashes, config hashes, and network endpoints.
func compareSnapshots(baseline *audit.SnapshotRow, current *TargetSnapshot) []DriftDelta {
	var deltas []DriftDelta
	if baseline == nil || current == nil {
		return deltas
	}

	var prevDeps map[string]string
	if err := json.Unmarshal([]byte(baseline.DependencyHashes), &prevDeps); err != nil && baseline.DependencyHashes != "" {
		fmt.Fprintf(os.Stderr, "[rescan] corrupt baseline dependency_hashes for %s: %v\n", baseline.TargetPath, err)
	}
	for file, hash := range current.DependencyHashes {
		prev, exists := prevDeps[file]
		if !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftDependencyChange,
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("new dependency manifest: %s", file),
				Current:     hash,
			})
		} else if prev != hash {
			deltas = append(deltas, DriftDelta{
				Type:        DriftDependencyChange,
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("dependency manifest modified: %s", file),
				Previous:    prev,
				Current:     hash,
			})
		}
	}
	for file, hash := range prevDeps {
		if _, exists := current.DependencyHashes[file]; !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftDependencyChange,
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("dependency manifest removed: %s", file),
				Previous:    hash,
			})
		}
	}

	var prevCfg map[string]string
	if err := json.Unmarshal([]byte(baseline.ConfigHashes), &prevCfg); err != nil && baseline.ConfigHashes != "" {
		fmt.Fprintf(os.Stderr, "[rescan] corrupt baseline config_hashes for %s: %v\n", baseline.TargetPath, err)
	}
	for file, hash := range current.ConfigHashes {
		prev, exists := prevCfg[file]
		if !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftConfigMutation,
				Severity:    "HIGH",
				Description: fmt.Sprintf("new config file: %s", file),
				Current:     hash,
			})
		} else if prev != hash {
			deltas = append(deltas, DriftDelta{
				Type:        DriftConfigMutation,
				Severity:    "HIGH",
				Description: fmt.Sprintf("config file modified: %s", file),
				Previous:    prev,
				Current:     hash,
			})
		}
	}
	for file, hash := range prevCfg {
		if _, exists := current.ConfigHashes[file]; !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftConfigMutation,
				Severity:    "HIGH",
				Description: fmt.Sprintf("config file removed: %s", file),
				Previous:    hash,
			})
		}
	}

	var prevEndpoints []string
	if err := json.Unmarshal([]byte(baseline.NetworkEndpoints), &prevEndpoints); err != nil && baseline.NetworkEndpoints != "" {
		fmt.Fprintf(os.Stderr, "[rescan] corrupt baseline network_endpoints for %s: %v\n", baseline.TargetPath, err)
	}
	prevSet := make(map[string]bool, len(prevEndpoints))
	for _, ep := range prevEndpoints {
		prevSet[ep] = true
	}
	curSet := make(map[string]bool, len(current.NetworkEndpoints))
	for _, ep := range current.NetworkEndpoints {
		curSet[ep] = true
	}

	for _, ep := range current.NetworkEndpoints {
		if !prevSet[ep] {
			deltas = append(deltas, DriftDelta{
				Type:        DriftNewEndpoint,
				Severity:    "HIGH",
				Description: fmt.Sprintf("new network endpoint detected: %s", ep),
				Current:     ep,
			})
		}
	}
	for _, ep := range prevEndpoints {
		if !curSet[ep] {
			deltas = append(deltas, DriftDelta{
				Type:        DriftRemovedEndpoint,
				Severity:    "INFO",
				Description: fmt.Sprintf("network endpoint removed: %s", ep),
				Previous:    ep,
			})
		}
	}

	// Fall back to the whole-tree content hash so code-only mutations that do
	// not alter dependencies, config files, or endpoints still surface as drift.
	if baseline.ContentHash != "" && current.ContentHash != "" &&
		baseline.ContentHash != current.ContentHash && len(deltas) == 0 {
		deltas = append(deltas, DriftDelta{
			Type:        DriftContentChange,
			Severity:    "MEDIUM",
			Description: "directory contents changed outside tracked dependency/config/endpoint surfaces",
			Previous:    baseline.ContentHash,
			Current:     current.ContentHash,
		})
	}

	return deltas
}

func findingDriftKey(f scanner.Finding) string {
	return strings.Join([]string{
		f.Scanner,
		f.Title,
		f.Location,
	}, "\x00")
}

func findingLabel(f scanner.Finding) string {
	if f.Location == "" {
		return f.Title
	}
	return fmt.Sprintf("%s (%s)", f.Title, f.Location)
}

// diffFindings compares two sets of findings and returns drift deltas.
func diffFindings(prev, curr []scanner.Finding) []DriftDelta {
	prevByKey := make(map[string]scanner.Finding, len(prev))
	for _, f := range prev {
		prevByKey[findingDriftKey(f)] = f
	}
	currByKey := make(map[string]scanner.Finding, len(curr))
	for _, f := range curr {
		currByKey[findingDriftKey(f)] = f
	}

	var deltas []DriftDelta

	for key, f := range currByKey {
		prevFinding, exists := prevByKey[key]
		if !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftNewFinding,
				Severity:    string(f.Severity),
				Description: fmt.Sprintf("new finding: %s (%s)", findingLabel(f), f.Severity),
				Current:     findingLabel(f),
				RuleID:      f.RuleID,
			})
			continue
		}
		if prevFinding.Severity != f.Severity {
			sev := prevFinding.Severity
			if audit.SeverityRank(string(f.Severity)) > audit.SeverityRank(string(prevFinding.Severity)) {
				sev = f.Severity
			}
			deltas = append(deltas, DriftDelta{
				Type:        DriftSeverityChange,
				Severity:    string(sev),
				Description: fmt.Sprintf("finding severity changed: %s (%s -> %s)", findingLabel(f), prevFinding.Severity, f.Severity),
				Previous:    string(prevFinding.Severity),
				Current:     string(f.Severity),
				RuleID:      f.RuleID,
			})
		}
	}

	for key, f := range prevByKey {
		if _, exists := currByKey[key]; !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftRemovedFinding,
				Severity:    "INFO",
				Description: fmt.Sprintf("finding resolved: %s (was %s)", findingLabel(f), f.Severity),
				Previous:    findingLabel(f),
				RuleID:      f.RuleID,
			})
		}
	}

	return deltas
}

// driftRuleIDs collects the distinct rule identifiers from a set
// of drift deltas, preserving discovery order and capping the
// result at max entries. Empty rule IDs are skipped so the
// `rule_ids=` suffix never carries empty tokens. The cap matches
// the convention used by every other emission surface in the
// gateway (hook handlers, proxy guardrail, inspect HTTP) so SIEM
// dashboards can rely on a uniform fanout budget.
func driftRuleIDs(deltas []DriftDelta, max int) []string {
	if max <= 0 || len(deltas) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(deltas))
	out := make([]string, 0, len(deltas))
	for _, d := range deltas {
		if d.RuleID == "" {
			continue
		}
		if seen[d.RuleID] {
			continue
		}
		seen[d.RuleID] = true
		out = append(out, d.RuleID)
		if len(out) >= max {
			break
		}
	}
	return out
}

// emitDriftAlerts logs drift deltas as alert events in the audit store.
func (w *InstallWatcher) emitDriftAlerts(evt InstallEvent, deltas []DriftDelta) {
	maxSev := "INFO"
	for _, d := range deltas {
		if audit.SeverityRank(d.Severity) > audit.SeverityRank(maxSev) {
			maxSev = d.Severity
		}
	}

	summary := summarizeDrift(deltas)
	detailsJSON, _ := json.Marshal(deltas)

	fmt.Fprintf(os.Stderr, "[rescan] drift detected in %s %s: %s\n", evt.Type, evt.Name, summary)

	// Surface the drift's distinct underlying rule identifiers
	// alongside the structured JSON details so SIEM queries can
	// pivot on `rule_ids` consistently with hook + proxy + inspect
	// emissions. The JSON details remain the source of truth for
	// per-delta info; the string suffix is the SIEM-friendly view.
	ruleIDs := driftRuleIDs(deltas, 8)
	details := string(detailsJSON)
	if len(ruleIDs) > 0 {
		details += " rule_ids=" + strings.Join(ruleIDs, ",")
	}

	event := audit.Event{
		// The row id is the webhook's event id (GAP-0218): the logger stamps its own copy.
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    string(audit.ActionDrift),
		Target:    evt.Path,
		Actor:     "defenseclaw-rescan",
		Details:   details,
		Severity:  maxSev,
	}
	if err := w.logger.LogEvent(event); err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] drift alert LogEvent failed for %s: %v\n", evt.Path, err)
	}

	w.recordWatcherEvent(context.Background(), "drift", string(evt.Type), "")

	if w.webhooks != nil {
		w.webhooks.Dispatch(event)
	}
}

func summarizeDrift(deltas []DriftDelta) string {
	counts := make(map[DriftType]int)
	for _, d := range deltas {
		counts[d.Type]++
	}

	var parts []string
	types := make([]DriftType, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return string(types[i]) < string(types[j]) })

	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s=%d", t, counts[t]))
	}
	return strings.Join(parts, " ")
}

func (w *InstallWatcher) snapshotForEvent(evt InstallEvent) (*TargetSnapshot, error) {
	switch evt.Type {
	case InstallMCP:
		return w.snapshotMCPServer(evt)
	default:
		if _, err := os.Stat(evt.Path); err != nil {
			return nil, err
		}
		return SnapshotTarget(evt.Path)
	}
}

func (w *InstallWatcher) snapshotMCPServer(evt InstallEvent) (*TargetSnapshot, error) {
	name := evt.Name
	entry, err := w.lookupMCPServer(evt)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal mcp server %s: %w", name, err)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])

	snap := &TargetSnapshot{
		ContentHash:      hash,
		DependencyHashes: map[string]string{},
		ConfigHashes: map[string]string{
			fmt.Sprintf("mcp.servers.%s", name): hash,
		},
		Timestamp: time.Now().UTC(),
	}
	if entry.URL != "" {
		snap.NetworkEndpoints = []string{entry.URL}
	}
	return snap, nil
}

// MCPEventPath is the key of an MCP server in the watcher: its event Path
// and target snapshot. A server a managed gateway read from a user home is
// keyed by its name, connector and home, so a second user's server with the
// same name has its own baseline and admission; any other server is keyed by
// its name.
func MCPEventPath(server config.MCPServerEntry) string {
	if server.Home == "" {
		return server.Name
	}
	return server.Name + "@" + server.Connector + ":" + server.Home
}

func (w *InstallWatcher) lookupMCPServer(evt InstallEvent) (*config.MCPServerEntry, error) {
	servers, err := w.readMCPServers()
	if err != nil {
		return nil, err
	}
	for _, server := range servers {
		if server.Name == evt.Name && MCPEventPath(server) == evt.Path {
			serverCopy := server
			return &serverCopy, nil
		}
	}
	return nil, os.ErrNotExist
}

func (w *InstallWatcher) scanTargetFor(evt InstallEvent) string {
	if evt.Type != InstallMCP {
		return evt.Path
	}
	entry, err := w.lookupMCPServer(evt)
	if err != nil {
		return evt.Name
	}
	if entry.URL != "" {
		return entry.URL
	}
	return entry.Name
}

// emitRescanResult fans a watcher rescan result through the
// generated v8 scan emission pipeline so the rescan's per-rule findings land
// in the forensic scan_results + scan_findings tables, generated finding and
// summary logs/metrics, and the sliding-window correlator. No alternate
// producer or provider fanout is reachable. Previously this path called
// audit.Store.InsertScanResult directly which wrote only the
// aggregate row and dropped every per-rule detection on the floor
// — making periodic rescans invisible to SIEM finding queries.
//
// Returns the generated scan ID so persistSnapshot can record it as
// the snapshot's baseline reference. On emission failure (writer or
// persistence error) returns the empty string and lets the
// snapshot store fall back to "" so callers don't see new failure modes.
func (w *InstallWatcher) emitRescanResult(ctx context.Context, result *scanner.ScanResult) string {
	if w == nil || w.logger == nil || result == nil {
		return ""
	}
	correlation := watcherScanCorrelation(
		ctx, rescanRunID(), watcherConnectorName(w.cfg),
	)
	err := w.logger.LogScanWithCorrelation(ctx, result, result.Verdict, correlation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] emit scan result for %s: %v\n", result.Target, err)
		return ""
	}
	return result.ScanID
}

// rescanRunID returns a fresh run ID for each rescan emission so
// the emitted scan rows are attributable to a specific cycle, and
// downstream correlator joins can scope findings to one rescan
// rather than blending cycles. Watchers don't carry a request_id
// (there's no HTTP request to correlate against), so the run_id is
// the only correlation key available — making it required.
func rescanRunID() string {
	return "rescan-" + uuid.New().String()
}
