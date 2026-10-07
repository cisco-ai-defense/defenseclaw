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
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/hermesskills"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// InstallType distinguishes between skill and MCP install events.
type InstallType string

const (
	InstallSkill  InstallType = "skill"
	InstallMCP    InstallType = "mcp"
	InstallPlugin InstallType = "plugin"
)

// String returns the string representation of the InstallType.
func (t InstallType) String() string { return string(t) }

// InstallEvent is emitted when the watcher detects a new skill or MCP server.
type InstallEvent struct {
	Type InstallType
	Name string
	Path string
	// Connector is the owning connector for this install, used to scope
	// per-connector enforcement on the admit path (most-specific-wins:
	// connector-scoped state, then the bare global state). Empty ⇒ resolve the
	// connector from the watcher config (watcherConnectorName) — preserves the
	// pre-existing global behavior for events that do not tag a connector.
	Connector string
	Timestamp time.Time
}

// Verdict is the outcome of running the admission gate on an install.
type Verdict string

const (
	VerdictBlocked   Verdict = "blocked"
	VerdictAllowed   Verdict = "allowed"
	VerdictClean     Verdict = "clean"
	VerdictRejected  Verdict = "rejected"
	VerdictWarning   Verdict = "warning"
	VerdictScanError Verdict = "scan-error"
)

// AdmissionResult captures the outcome for a single install event.
type AdmissionResult struct {
	Event         InstallEvent
	Verdict       Verdict
	Reason        string
	MaxSeverity   string
	FindingCount  int
	InstallAction string
	FileAction    string
	RuntimeAction string
	// ScanID is the scan_results row admission recorded, or "" when no
	// scan was logged. It becomes the rescan baseline's scan (GAP-2507).
	ScanID string
}

// OnAdmission is called after each install event is processed.
type OnAdmission func(AdmissionResult)

// InstallWatcher monitors OpenClaw skill directories for new installs
// and runs the admission gate (block → allow → scan) on each detection.
// MCP servers are managed via “defenseclaw mcp set/unset“ rather than
// filesystem watching.
// WebhookDispatcher is implemented by gateway.WebhookDispatcher. Declared as
// an interface here to avoid an import cycle (watcher → gateway).
type WebhookDispatcher interface {
	Dispatch(event audit.Event)
}

type InstallWatcher struct {
	cfg        *config.Config
	skillDirs  []string
	pluginDirs []string
	// managedArtifacts are exact connector-owned plugin files. They remain
	// visible to connector lifecycle/Doctor, but ordinary plugin scanners must
	// not inspect or quarantine DefenseClaw's own bridge artifact.
	managedArtifacts []string
	// bundledPlugin reports whether a plugin path is DefenseClaw's own plugin,
	// byte-identical to the copy this gateway ships (OpenClaw, GAP-1525).
	bundledPlugin func(path string) bool
	// bundledPluginDir is where the connector writes that plugin at gateway
	// start. The startup rescan defers it until Setup has refreshed it.
	bundledPluginDir string
	// startupRescanDone is set after the first rescan cycle (rescan goroutine
	// only).
	startupRescanDone bool
	// startupAdmitRoots are the skill and plugin roots that already held
	// baselines when the startup rescan began (rescan goroutine only).
	startupAdmitRoots map[InstallType][]string
	// markedWatchRoots caches the root markers written by this process
	// (rescan goroutine only).
	markedWatchRoots map[string]bool
	store            *audit.Store
	logger           *audit.Logger
	opa              *policy.Engine
	webhooks         WebhookDispatcher
	debounce         time.Duration
	onAdmit          OnAdmission

	mu      sync.Mutex
	pending map[string]time.Time // path → first-seen, for debounce

	// pluginWaiting holds plugin-root folders that had nothing to admit yet
	// (empty or category folders) and are watched for what lands in them;
	// addWatch adds such a watch. Both are used on the Run goroutine only
	// (GAP-2449).
	pluginWaiting map[string]struct{}
	addWatch      func(dir string)

	observabilityV8Mu sync.RWMutex
	observabilityV8   ObservabilityV8Runtime

	// configSource returns the live config (the sidecar's published
	// snapshot), so asset_policy and admission edits apply to the next
	// admission without a watcher restart. Nil uses cfg.
	configSource func() *config.Config

	// policySource returns the live generation's prepared OPA admission
	// query (nil when that generation has none), so a changed Rego module
	// applies to the next admission. Nil uses opa.
	policySource func() *policy.Prepared

	// policyStamp returns the live generation's effective policy digest and
	// applied generation for the admission decision records (absent before
	// the first generation and under the Secure Client integration).
	policyStamp func() (digest observability.Optional[string], generation observability.Optional[int64])

	// scannerFactory resolves the scanner for an event. Defaults to
	// scannerFor; tests inject a fake to observe scan invocations without
	// shelling out to the real scanner binaries.
	scannerFactory func(InstallEvent) scanner.Scanner

	// rulePackSource returns the guardrail rule pack the install-time scan of
	// a connector's skills applies on top of the skill scanner, or nil when
	// that connector's scope selects none. Nil applies no overlay.
	rulePackSource func(connector string) *guardrail.RulePack

	// rootConnectors tags each watched root with the connector that owns it,
	// longest root first. A managed gateway watches every enrolled user's
	// connector folders at once, so an event's connector comes from the root
	// that holds it (GAP-0132). Empty means every root belongs to
	// watcherConnectorName.
	rootConnectors []rootConnector

	// mcpServers lists the MCP servers admission and the rescan see. Nil
	// reads the connector config in the gateway's own home.
	mcpServers func() ([]config.MCPServerEntry, error)
	// admitNewMCP runs install admission for an MCP server that appears
	// after the first rescan cycle (set with SetMCPServerSource): a managed
	// computer has no `mcp set`, so a user adding a server to their agent is
	// its install.
	admitNewMCP bool

	// rescanNow asks the rescan loop for a cycle before its interval ends.
	rescanNow chan struct{}

	// addedMCP names the MCP servers AdmitAddedMCPServers queued; admitMCPNow
	// wakes the loop that admits them outside the rescan cycle (GAP-0254).
	addedMCPMu  sync.Mutex
	addedMCP    map[string]bool
	admitMCPNow chan struct{}
	// mcpMu serializes MCP admission between that loop and the rescan
	// cycle, so a server is admitted once.
	mcpMu sync.Mutex
}

type rootConnector struct {
	root      string
	connector string
}

// newScanner resolves the scanner for evt via the injectable factory, falling
// back to the config-driven scannerFor when no factory is installed.
func (w *InstallWatcher) newScanner(evt InstallEvent) scanner.Scanner {
	if w.scannerFactory != nil {
		return w.scannerFactory(evt)
	}
	return w.scannerFor(evt)
}

// New creates an InstallWatcher. The opa parameter may be nil to fall back
// to the built-in Go admission logic. Watcher observability is exclusively
// emitted through the audit logger's generated v8 runtime.
func New(cfg *config.Config, skillDirs, pluginDirs []string, store *audit.Store, logger *audit.Logger, opa *policy.Engine, onAdmit OnAdmission) *InstallWatcher {
	debounce := time.Duration(cfg.Watch.DebounceMs) * time.Millisecond
	if debounce <= 0 {
		debounce = 500 * time.Millisecond
	}
	return &InstallWatcher{
		cfg:        cfg,
		skillDirs:  skillDirs,
		pluginDirs: pluginDirs,
		store:      store,
		logger:     logger,
		opa:        opa,
		debounce:   debounce,
		onAdmit:    onAdmit,
		pending:    make(map[string]time.Time),
		rescanNow:  make(chan struct{}, 1),

		admitMCPNow: make(chan struct{}, 1),
	}
}

// SetRootConnectors tags watched roots with the connector that owns each one
// (root path -> connector name). Call it before Run.
func (w *InstallWatcher) SetRootConnectors(roots map[string]string) {
	w.rootConnectors = w.rootConnectors[:0]
	for root, connectorName := range roots {
		abs, err := filepath.Abs(filepath.Clean(root))
		if err != nil || strings.TrimSpace(connectorName) == "" {
			continue
		}
		w.rootConnectors = append(w.rootConnectors, rootConnector{root: abs, connector: strings.ToLower(strings.TrimSpace(connectorName))})
	}
	sort.Slice(w.rootConnectors, func(i, j int) bool {
		return len(w.rootConnectors[i].root) > len(w.rootConnectors[j].root)
	})
}

// SetMCPServerSource replaces where admission and the rescan read the MCP
// servers (a managed gateway reads every enrolled user's). Call it before Run.
func (w *InstallWatcher) SetMCPServerSource(source func() ([]config.MCPServerEntry, error)) {
	w.mcpServers = source
	w.admitNewMCP = source != nil
}

// RequestRescan runs a rescan cycle soon, without waiting for the interval.
// It never blocks; a request while one is pending is merged.
func (w *InstallWatcher) RequestRescan() {
	if w == nil || w.rescanNow == nil {
		return
	}
	select {
	case w.rescanNow <- struct{}{}:
	default:
	}
}

// AdmitAddedMCPServers runs install admission now for MCP servers the caller
// saw appear, outside the rescan cycle (GAP-0254): after an upgrade the cycle
// rescans every target and takes minutes, and a server a user just added
// must not wait for it. It never blocks.
func (w *InstallWatcher) AdmitAddedMCPServers(names []string) {
	if w == nil || !w.admitNewMCP || len(names) == 0 {
		return
	}
	w.addedMCPMu.Lock()
	if w.addedMCP == nil {
		w.addedMCP = map[string]bool{}
	}
	for _, name := range names {
		w.addedMCP[name] = true
	}
	w.addedMCPMu.Unlock()
	select {
	case w.admitMCPNow <- struct{}{}:
	default:
	}
}

func (w *InstallWatcher) addedMCPLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.admitMCPNow:
			w.admitAddedMCPServers(ctx)
		}
	}
}

// admitAddedMCPServers admits each queued server that has no baseline yet.
func (w *InstallWatcher) admitAddedMCPServers(ctx context.Context) {
	w.addedMCPMu.Lock()
	names := w.addedMCP
	w.addedMCP = nil
	w.addedMCPMu.Unlock()
	servers, err := w.readMCPServers()
	if err != nil {
		return
	}
	for _, server := range servers {
		if ctx.Err() != nil {
			return
		}
		if !names[server.Name] || server.Bundled {
			continue
		}
		evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: server.Name, Connector: server.Connector, Timestamp: time.Now().UTC()}
		w.mcpMu.Lock()
		if _, err := w.store.GetTargetSnapshot(string(evt.Type), evt.Path); errors.Is(err, sql.ErrNoRows) {
			if snap, err := w.snapshotForEvent(evt); err == nil {
				fmt.Fprintf(os.Stderr, "[watch] mcp %s was added; running install admission\n", evt.Name)
				res := w.runAdmission(ctx, evt)
				if w.onAdmit != nil {
					w.onAdmit(res)
				}
				w.persistSnapshot(evt, snap, res.ScanID, w.cachedFingerprint(evt, nil))
			}
		}
		w.mcpMu.Unlock()
	}
}

// readMCPServers is the MCP server list admission and the rescan use.
func (w *InstallWatcher) readMCPServers() ([]config.MCPServerEntry, error) {
	if w.mcpServers != nil {
		return w.mcpServers()
	}
	return w.cfg.ReadMCPServers()
}

// connectorForPath is the connector that owns path: the tagged watched root
// that holds it, else the watcher's own connector.
func (w *InstallWatcher) connectorForPath(path string) string {
	if len(w.rootConnectors) > 0 && strings.TrimSpace(path) != "" {
		if abs, err := filepath.Abs(filepath.Clean(path)); err == nil {
			for _, rc := range w.rootConnectors {
				if pathWithinRoot(abs, rc.root) {
					return rc.connector
				}
			}
		}
	}
	return watcherConnectorName(w.cfg)
}

// pathWithinRoot reports whether path is root or below it (case-insensitive
// on Windows).
func pathWithinRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(path), filepath.VolumeName(root)) {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// SetPolicySource binds the live generation's prepared OPA admission
// query. Call it before Run.
func (w *InstallWatcher) SetPolicySource(source func() *policy.Prepared) {
	w.policySource = source
}

// SetPolicyStamp binds the effective policy digest and generation the
// admission decision records carry. Call it before Run.
func (w *InstallWatcher) SetPolicyStamp(stamp func() (observability.Optional[string], observability.Optional[int64])) {
	w.policyStamp = stamp
}

// SetRulePackSource binds the live generation's guardrail rule pack for a
// connector, so a skill is scanned at install with the pack
// `defenseclaw skill scan` applies to it. Call it before Run.
func (w *InstallWatcher) SetRulePackSource(source func(connector string) *guardrail.RulePack) {
	w.rulePackSource = source
}

// SetConfigSource binds the live config admission decisions read.
func (w *InstallWatcher) SetConfigSource(source func() *config.Config) {
	w.configSource = source
}

// liveConfig is the config admission decisions read: the bound source's
// current snapshot, else the config the watcher started with.
func (w *InstallWatcher) liveConfig() *config.Config {
	if w.configSource != nil {
		if cfg := w.configSource(); cfg != nil {
			return cfg
		}
	}
	return w.cfg
}

// SetManagedArtifacts binds exact connector-owned plugin paths before Run.
// Paths are matched exactly; parent directories and sibling plugins receive no
// exemption.
func (w *InstallWatcher) SetManagedArtifacts(paths []string) {
	w.managedArtifacts = w.managedArtifacts[:0]
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		absolute, err := filepath.Abs(filepath.Clean(trimmed))
		if err != nil {
			continue
		}
		duplicate := false
		for _, existing := range w.managedArtifacts {
			if sameWatcherPath(existing, absolute) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			w.managedArtifacts = append(w.managedArtifacts, absolute)
		}
	}
}

// SetBundledPluginCheck binds the connector's check for its own shipped plugin.
// A plugin that passes is DefenseClaw's own and is not scanned; one with an
// added or changed file fails the check and is scanned like any other.
func (w *InstallWatcher) SetBundledPluginCheck(check func(path string) bool) {
	w.bundledPlugin = check
}

// SetBundledPluginDir records where the connector installs its own plugin.
func (w *InstallWatcher) SetBundledPluginDir(dir string) {
	w.bundledPluginDir = dir
}

// isBundledPluginDir reports whether path is the connector's own plugin dir.
func (w *InstallWatcher) isBundledPluginDir(path string) bool {
	if w.bundledPluginDir == "" {
		return false
	}
	got, err1 := filepath.Abs(path)
	want, err2 := filepath.Abs(w.bundledPluginDir)
	return err1 == nil && err2 == nil && filepath.Clean(got) == filepath.Clean(want)
}

// isOwnPlugin reports whether a plugin path is connector-managed or
// DefenseClaw's own unmodified plugin. Admission and the periodic rescan both
// skip such plugins, so neither raises findings on DefenseClaw's own code.
func (w *InstallWatcher) isOwnPlugin(path string) bool {
	return w.isManagedArtifact(path) || (w.bundledPlugin != nil && w.bundledPlugin(path))
}

// secureClientActive reports the Secure Client deployment, whose install
// watcher keeps its audit rows and admission behavior as they were.
func (w *InstallWatcher) secureClientActive() bool {
	return w.cfg != nil && w.cfg.SecureClientIntegration()
}

// allowedAuditReason names why install admission allowed an asset before any
// scan: the operator turned admission.<type>.scan_on_install off, or the asset
// is on an allow list (or first-party allow list). The audit row used to say
// "allow-listed" for both, so an MCP server admitted only because
// scan_on_install is false looked like an allow-list entry (GAP-0203).
func (w *InstallWatcher) allowedAuditReason(verdictReason string) string {
	if !w.secureClientActive() && strings.HasPrefix(verdictReason, "scan_on_install disabled") {
		return "scan-disabled"
	}
	return "allow-listed"
}

func (w *InstallWatcher) isManagedArtifact(path string) bool {
	for _, managedPath := range w.managedArtifacts {
		if sameWatcherPath(path, managedPath) {
			return true
		}
	}
	return false
}

// SetWebhookDispatcher attaches a webhook dispatcher for outbound notifications.
func (w *InstallWatcher) SetWebhookDispatcher(d WebhookDispatcher) {
	w.webhooks = d
}

// Run starts watching configured directories. It blocks until ctx is cancelled.
func (w *InstallWatcher) Run(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watcher: create fsnotify watcher: %w", err)
	}
	defer fsw.Close()

	watched := 0
	watchedDirs := make(map[string]struct{})
	w.addWatch = func(dir string) { addDirWatches(fsw, dir, 0, watchedDirs) }
	var deferredDirs [][2]string // {dir, kind} not created because an agent installer owns them
	watchOnce := func(dir, kind string) bool {
		absolute, absErr := filepath.Abs(dir)
		if absErr != nil {
			absolute = filepath.Clean(dir)
		}
		key := strings.ToLower(filepath.Clean(absolute))
		if _, exists := watchedDirs[key]; exists {
			return true
		}
		if createsAgentOwnedDir(dir) {
			// Watched once the agent's own installer creates it (GAP-2354).
			deferredDirs = append(deferredDirs, [2]string{dir, kind})
			fmt.Printf("[watch] %s dir %s does not exist yet; watching it once the agent creates it\n", kind, dir)
			return false
		}
		created, err := ensureAndWatch(fsw, dir)
		if len(created) > 0 {
			// Uninstall removes these again while they are empty (and the
			// OpenCode teardown removes its own).
			if recordErr := gatewayconnector.RecordWatcherCreatedDirs(w.cfg.DataDir, created); recordErr != nil {
				fmt.Fprintf(os.Stderr, "[watch] record created dirs: %v\n", recordErr)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[watch] %s dir %s: %v (skipping)\n", kind, dir, err)
			return false
		}
		watchedDirs[key] = struct{}{}
		watched++
		fmt.Printf("[watch] monitoring %s dir: %s\n", kind, dir)
		return true
	}
	for _, dir := range w.skillDirs {
		if watchOnce(dir, "skill") {
			// Claude Code syncs account skills two levels down
			// (skills/synced/<account>/<skill>); watch those folders too so
			// a newly synced skill is scanned on arrival (GAP-1409).
			synced := filepath.Join(dir, "synced")
			if depth, ok := w.claudeSyncedDepth(synced); ok && depth == 0 {
				addDirWatches(fsw, synced, 1, watchedDirs)
			}
		}
	}
	for _, dir := range w.pluginDirs {
		if !watchOnce(dir, "plugin") {
			continue
		}
		w.watchExistingPluginFolders(dir)
		if w.connectorForPath(dir) == "claudecode" &&
			strings.EqualFold(filepath.Base(filepath.Clean(dir)), "cache") {
			addClaudeCacheWatches(fsw, dir, watchedDirs)
		}
	}

	if watched == 0 {
		return fmt.Errorf("watcher: no directories to watch — check claw.mode and claw.home_dir")
	}

	_ = w.logger.LogAction(string(audit.ActionWatchStart), "", fmt.Sprintf("dirs=%d debounce=%s", watched, w.debounce))

	if w.cfg.Watch.RescanEnabled {
		go w.rescanLoop(ctx)
	}
	if w.admitNewMCP {
		go w.addedMCPLoop(ctx)
	}

	ticker := time.NewTicker(w.debounce)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = w.logger.LogAction(string(audit.ActionWatchStop), "", "context cancelled")
			return ctx.Err()

		case event, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if event.Op&(fsnotify.Rename|fsnotify.Remove) != 0 {
				forgetDirWatches(fsw, event.Name, watchedDirs)
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if w.connectorForPath(event.Name) == "claudecode" {
				if depth, inside := w.claudeCacheDepth(event.Name); inside {
					if info, statErr := os.Stat(event.Name); statErr == nil &&
						info.IsDir() && depth < 3 {
						addClaudeCacheWatches(fsw, event.Name, watchedDirs)
						w.queueExistingClaudePlugins(ctx, event.Name, depth)
					}
					if depth != 3 {
						continue
					}
				}
			}
			if depth, inside := w.claudeSyncedDepth(event.Name); inside {
				if info, statErr := os.Stat(event.Name); statErr != nil || !info.IsDir() {
					continue
				}
				switch depth {
				case 0:
					// The synced folder itself: watch it and its account
					// folders; the event below expands it into its skills.
					addDirWatches(fsw, event.Name, 1, watchedDirs)
				case 1:
					// A new account folder: watch it and queue the skills
					// already inside (they can land before the watch).
					addDirWatches(fsw, event.Name, 0, watchedDirs)
					children, _ := os.ReadDir(event.Name)
					for _, child := range children {
						if child.IsDir() && !strings.HasPrefix(child.Name(), ".") {
							w.queueSyncedSkill(ctx, filepath.Join(event.Name, child.Name()))
						}
					}
					continue
				default:
					w.queueSyncedSkill(ctx, event.Name)
					continue
				}
			}
			queued := event.Name
			if !w.isDirectChildDir(event.Name) {
				var ok bool
				if queued, ok = w.waitingPluginEvent(event.Name); !ok {
					continue
				}
			}
			evtType := "create"
			if event.Op&fsnotify.Rename != 0 {
				evtType = "rename"
			}
			w.recordWatcherEvent(ctx, evtType, w.classifyEvent(queued).Type.String(), "")
			w.mu.Lock()
			if _, exists := w.pending[queued]; !exists {
				w.pending[queued] = time.Now()
			}
			w.mu.Unlock()

		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			w.recordWatcherError(ctx)
			fmt.Fprintf(os.Stderr, "[watch] fsnotify error: %v\n", err)

		case <-ticker.C:
			if len(deferredDirs) > 0 {
				waiting := deferredDirs
				deferredDirs = nil
				for _, entry := range waiting {
					if _, statErr := os.Lstat(entry[0]); statErr != nil {
						deferredDirs = append(deferredDirs, entry)
						continue
					}
					if watchOnce(entry[0], entry[1]) && entry[1] == "plugin" {
						w.watchExistingPluginFolders(entry[0])
					}
				}
			}
			w.processPending(ctx)
		}
	}
}

func (w *InstallWatcher) processPending(ctx context.Context) {
	w.mu.Lock()
	now := time.Now()
	var ready []string
	for path, firstSeen := range w.pending {
		if now.Sub(firstSeen) >= w.debounce {
			ready = append(ready, path)
		}
	}
	for _, p := range ready {
		delete(w.pending, p)
	}
	w.mu.Unlock()

	for _, path := range ready {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		for _, evt := range w.pendingInstallEvents(path) {
			snap := w.admissionSnapshot(evt)
			result := w.runAdmission(ctx, evt)
			w.recordAdmissionBaseline(evt, snap, result.ScanID)
			if w.onAdmit != nil {
				w.onAdmit(result)
			}
		}
	}
}

// pendingInstallEvents expands a top-level Hermes category notification into
// the actual nested SKILL.md identities. A provenance/discovery failure keeps
// the original category event so it fails open to scanning.
func (w *InstallWatcher) pendingInstallEvents(path string) []InstallEvent {
	fallback := w.classifyEvent(path)
	if depth, ok := w.claudeSyncedDepth(path); ok && depth == 2 {
		fallback.Type = InstallSkill
		return []InstallEvent{fallback}
	}
	if synced, ok := claudeSyncedSkillDirs(path); ok {
		out := make([]InstallEvent, 0, len(synced))
		for _, skill := range synced {
			evt := w.classifyEvent(skill)
			evt.Type = InstallSkill
			out = append(out, evt)
		}
		return out
	}
	if fallback.Type == InstallPlugin {
		if events, ok := w.pluginFolderEvents(path); ok {
			return events
		}
	}
	for _, root := range w.skillDirs {
		discover, _ := hermesSkillsDiscover(root)
		if discover == nil || !watcherPathAtOrBelow(path, root) {
			continue
		}
		entries, err := discover(root, hermesskills.DefaultDirectoryLimit)
		if err != nil {
			return []InstallEvent{fallback}
		}
		out := make([]InstallEvent, 0, len(entries))
		for _, entry := range entries {
			if !watcherPathAtOrBelow(entry.Path, path) {
				continue
			}
			out = append(out, InstallEvent{
				Type:      InstallSkill,
				Name:      entry.Name,
				Path:      entry.Path,
				Connector: "hermes",
				Timestamp: time.Now().UTC(),
			})
		}
		if len(out) > 0 {
			return out
		}
		return []InstallEvent{fallback}
	}
	return []InstallEvent{fallback}
}

func (w *InstallWatcher) classifyEvent(path string) InstallEvent {
	installType := InstallSkill
	name := filepath.Base(path)
	owner := w.connectorForPath(path)
	if owner == "claudecode" {
		if pluginID, isPlugin := w.claudePluginIdentity(path); isPlugin {
			installType = InstallPlugin
			name = pluginID
		}
		return InstallEvent{
			Type:      installType,
			Name:      name,
			Path:      path,
			Connector: "claudecode",
			Timestamp: time.Now().UTC(),
		}
	}
	pathAbs, _ := filepath.Abs(path)
	for _, dir := range w.pluginDirs {
		abs, _ := filepath.Abs(dir)
		if strings.HasPrefix(pathAbs, abs) {
			installType = InstallPlugin
			break
		}
	}

	return InstallEvent{
		Type:      installType,
		Name:      name,
		Path:      path,
		Connector: owner,
		Timestamp: time.Now().UTC(),
	}
}

func (w *InstallWatcher) claudePluginIdentity(path string) (string, bool) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	for _, root := range w.pluginDirs {
		rootAbs, absErr := filepath.Abs(root)
		if absErr != nil {
			continue
		}
		relative, relErr := filepath.Rel(rootAbs, pathAbs)
		if relErr != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		parts := strings.FieldsFunc(relative, func(r rune) bool {
			return r == '/' || r == '\\'
		})
		switch {
		case strings.EqualFold(filepath.Base(rootAbs), "cache") && len(parts) == 3:
			return parts[1] + "@" + parts[0], true
		case strings.EqualFold(filepath.Base(rootAbs), "skills") &&
			len(parts) == 1 && isClaudeSkillsPlugin(pathAbs):
			return claudeSkillsPluginIdentity(pathAbs), true
		}
	}
	return "", false
}

// eventConnector resolves the connector that owns an install event: the
// connector tagged on the event when present, otherwise the watcher's own
// connector (watcherConnectorName). This keeps the admit path correct for
// events that do not carry a Connector (e.g. the rescan enumerator), which
// previously always resolved via watcherConnectorName.
func (w *InstallWatcher) eventConnector(evt InstallEvent) string {
	if c := strings.TrimSpace(evt.Connector); c != "" {
		return c
	}
	if evt.Type != InstallMCP {
		return w.connectorForPath(evt.Path)
	}
	return watcherConnectorName(w.cfg)
}

// runAdmission applies the full admission gate: block → allow → scan.
// When the OPA engine is available it delegates the verdict decision to
// Rego policy; otherwise it falls back to the built-in Go logic.
func (w *InstallWatcher) runAdmission(ctx context.Context, evt InstallEvent) (res AdmissionResult) {
	if evt.Type == InstallPlugin && w.isManagedArtifact(evt.Path) {
		return AdmissionResult{
			Event:   evt,
			Verdict: VerdictAllowed,
			Reason:  "connector-managed plugin is lifecycle-owned and discovery-only",
		}
	}
	if evt.Type == InstallPlugin && w.bundledPlugin != nil && w.bundledPlugin(evt.Path) {
		return AdmissionResult{
			Event:   evt,
			Verdict: VerdictAllowed,
			Reason:  "DefenseClaw's own plugin, identical to the bundled copy",
		}
	}
	// Vendor-managed skills remain visible to inventory, but
	// must never enter scanner or enforcement paths. Check both the lexical
	// and resolved path so an alias outside a bundle cannot bypass the boundary.
	if evt.Type == InstallSkill && isBundledSkillWatchPath(evt.Path) {
		return AdmissionResult{
			Event:   evt,
			Verdict: VerdictAllowed,
			Reason:  "vendor-bundled skill is discovery-only",
		}
	}

	pe := enforce.NewPolicyEngine(w.store)
	targetType := string(evt.Type)
	policyID := enforce.PolicyStableID(w.cfg.PolicyDir)
	ctx, admissionTrace := w.startAdmissionTraceV8(ctx, evt, targetType, policyID)
	// SLO timer: measure watcher-detection → admission-decision wall
	// time so every run feeds defenseclaw.slo.block.latency. Blocked
	// verdicts drive the <2000ms SLO dashboard; allowed/clean still
	// populate the histogram so operators can compare distributions.
	admissionStart := time.Now()
	defer func() {
		_ = admissionTrace.end(res)
		w.recordBlockSLO(ctx, targetType, float64(time.Since(admissionStart).Milliseconds()))
	}()

	w.logAssetDiscovered(
		ctx, evt,
		fmt.Sprintf("type=%s name=%s", targetType, evt.Name), "detected",
	)

	cfg := w.liveConfig()
	connector := w.eventConnector(evt)
	assetDecision := cfg.EvaluateAssetPolicy(w.withMCPDefinition(cfg, evt, config.AssetPolicyInput{
		TargetType:     targetType,
		Name:           evt.Name,
		Connector:      connector,
		SourcePath:     evt.Path,
		RuntimeSurface: "watcher",
	}))
	if assetDecision.Enabled && assetDecision.RawAction == "block" {
		if assetDecision.Action == "block" {
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=%s source=%s", targetType, assetDecision.Reason, assetDecision.Source))
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: assetDecision.Reason}
			return res
		}
	}

	if res, done := w.legacyAllowPathMismatch(ctx, cfg, evt, targetType); done {
		return res
	}

	// Phase 1: pre-scan evaluation (no scan_result yet). The operator lists
	// come from asset_policy; an allow entry pinned to a source path never
	// transfers to another on-disk asset with the same name (F-2867).
	input := w.admissionInputFor(cfg, evt, targetType, connector)
	out := w.evaluateAdmission(ctx, input)
	switch out.Verdict {
	case "blocked":
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s reason=blocked", targetType))
		w.enforceBlock(ctx, evt)
		w.recordAdmission(ctx, "blocked", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: out.Reason}
		return res
	case "rejected":
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s reason=policy-rejected", targetType))
		w.enforceBlock(ctx, evt)
		w.recordAdmission(ctx, "rejected", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictRejected, Reason: out.Reason}
		return res
	case "allowed":
		_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
			fmt.Sprintf("type=%s reason=%s", targetType, w.allowedAuditReason(out.Reason)))
		w.recordAdmission(ctx, "allowed", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
		return res
	}
	// verdict == "scan" → proceed to scanning below

	// Phase 2: Scan.
	s := w.newScanner(evt)
	if s == nil {
		w.recordAdmission(ctx, "scan-error", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictScanError, Reason: "no scanner available"}
		return res
	}

	scanCtx, cancel := context.WithTimeout(ctx, w.scanTimeout(evt))
	defer cancel()

	// An MCP event's Path is its watcher key; the scanner gets the server.
	result, err := s.Scan(scanCtx, w.scanTargetFor(evt))
	if err != nil {
		_ = w.logger.LogAction(string(audit.ActionInstallScanError), evt.Path,
			fmt.Sprintf("type=%s scanner=%s error=%v", targetType, s.Name(), err))
		w.recordScanError(ctx, s.Name(), targetType, classifyWatcherScanError(err))
		// Avarice F-3187: a scanner error must NOT leave the
		// freshly-detected install in place. The legacy code
		// recorded `scan-error` and returned without quarantine,
		// blocking, or disabling the artifact, so a malicious
		// skill/plugin that crashed its scanner stayed installed.
		// Treat scanner failures as fail-closed: enforce a block
		// (which quarantines + disables per fallback policy) before
		// surfacing the verdict to the sidecar.
		w.enforceBlock(ctx, evt)
		_ = w.logger.LogAction("install-blocked", evt.Path,
			fmt.Sprintf("type=%s reason=scanner-error scanner=%s (F-3187)",
				targetType, s.Name()))
		w.recordAdmission(ctx, "scan-error", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictBlocked,
			Reason:        fmt.Sprintf("scanner failure (fail-closed): %v", err),
			InstallAction: "block",
		}
		return res
	}

	// Phase 3: post-scan evaluation. Re-read the live config so a block or
	// allow added while the scan was running wins.
	input = w.admissionInputFor(w.liveConfig(), evt, targetType, connector)
	input.ScanResult = &policy.ScanResultInput{
		MaxSeverity:   string(result.MaxSeverity()),
		TotalFindings: len(result.Findings),
		ScannerName:   s.Name(),
		Findings:      toFindingInputs(result.Findings),
	}
	if input.BlockListed() {
		reason := fmt.Sprintf("%s %q is on the block list — rejected", targetType, evt.Name)
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s reason=blocked-post-scan", targetType))
		scanID := w.logScanID(ctx, evt, result, "blocked")
		w.enforceBlock(ctx, evt)
		w.recordAdmission(ctx, "blocked", targetType)
		res = AdmissionResult{
			ScanID: scanID,
			Event:  evt, Verdict: VerdictBlocked, Reason: reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "block",
		}
		return res
	}
	if input.AllowListed() {
		reason := fmt.Sprintf("scan found findings but %s %q is allow-listed — skipping enforcement", targetType, evt.Name)
		_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
			fmt.Sprintf("type=%s reason=allow-listed-post-scan", targetType))
		scanID := w.logScanID(ctx, evt, result, "allowed")
		w.recordAdmission(ctx, "allowed", targetType)
		res = AdmissionResult{
			ScanID: scanID,
			Event:  evt, Verdict: VerdictAllowed, Reason: reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "allow",
		}
		return res
	}

	out = w.evaluateAdmission(ctx, input)
	w.applyPostScanEnforcement(ctx, pe, out, evt, targetType, result, s.Name())
	scanID := w.logScanID(ctx, evt, result, out.Verdict)
	w.recordAdmission(ctx, out.Verdict, targetType)
	res = AdmissionResult{
		ScanID: scanID,
		Event:  evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason,
		MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
		InstallAction: out.InstallAction,
		FileAction:    out.FileAction,
		RuntimeAction: out.RuntimeAction,
	}
	return res
}

// admissionInputFor builds the admission input from config: the compiled
// admission: for the asset type and the asset_policy block/allow lists that
// apply to the event's connector. Secure Client hosts keep their operator
// rows in the actions table, unchanged.
func (w *InstallWatcher) admissionInputFor(cfg *config.Config, evt InstallEvent, targetType, connector string) policy.AdmissionInput {
	block, allow := policy.AssetPolicyListsFor(cfg, w.withMCPDefinition(cfg, evt, config.AssetPolicyInput{
		TargetType: targetType, Name: evt.Name, Connector: connector, SourcePath: evt.Path,
	}))
	if cfg.SecureClientIntegration() {
		block, allow = w.legacyListEntries("block"), w.legacyListEntries("allow")
	}
	return policy.AdmissionInput{
		TargetType: targetType,
		TargetName: evt.Name,
		Path:       evt.Path,
		BlockList:  block,
		AllowList:  allow,
		Admission:  policy.AdmissionFor(policy.CompileAdmission(cfg), targetType),
	}
}

// withMCPDefinition adds how an MCP server starts (URL, command, args,
// transport) to its asset_policy input, so a rule pinned to the server
// definition matches it here as it does in mcp set: the shape mcp allow
// writes and the url/command/args_prefix/transport rules admins write
// (GAP-0371). Without it the watcher matched a pinned rule against a name
// alone, which never matches. A Secure Client host keeps the name-only
// input of main (issue #1092).
func (w *InstallWatcher) withMCPDefinition(cfg *config.Config, evt InstallEvent, in config.AssetPolicyInput) config.AssetPolicyInput {
	if evt.Type != InstallMCP || cfg == nil || cfg.SecureClientIntegration() {
		return in
	}
	if entry, err := w.lookupMCPServer(evt); err == nil {
		in.URL, in.Command, in.Args, in.Transport = entry.URL, entry.Command, entry.Args, entry.Transport
	}
	return in
}

// legacyListEntries is the Secure Client operator list read from the
// actions table, unchanged.
func (w *InstallWatcher) legacyListEntries(value string) []policy.ListEntry {
	if w.store == nil {
		return nil
	}
	entries, err := w.store.ListByAction("install", value)
	if err != nil {
		return nil
	}
	out := make([]policy.ListEntry, len(entries))
	for i, e := range entries {
		out[i] = policy.ListEntry{TargetType: e.TargetType, TargetName: e.TargetName, Reason: e.Reason}
	}
	return out
}

// legacyAllowPathMismatch is the Secure Client F-2867 check, unchanged: an
// allow row that recorded a source_path fails closed for an asset at another
// path. Elsewhere the asset_policy source_path_contains pin does this.
func (w *InstallWatcher) legacyAllowPathMismatch(ctx context.Context, cfg *config.Config, evt InstallEvent, targetType string) (AdmissionResult, bool) {
	if !cfg.SecureClientIntegration() || w.store == nil {
		return AdmissionResult{}, false
	}
	existing, _ := w.store.GetAction(targetType, evt.Name)
	if existing == nil || existing.Actions.Install != "allow" || existing.SourcePath == "" || existing.SourcePath == evt.Path {
		return AdmissionResult{}, false
	}
	_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
		fmt.Sprintf("reason=allow-path-mismatch type=%s name=%s allowed_path=%q presented_path=%q (F-2867)",
			targetType, evt.Name, existing.SourcePath, evt.Path))
	w.enforceBlock(ctx, evt)
	w.recordAdmission(ctx, "blocked", targetType)
	return AdmissionResult{
		Event:   evt,
		Verdict: VerdictBlocked,
		Reason:  "allow entry pinned to different source_path; failing closed (F-2867)",
	}, true
}

// evaluateAdmission runs the Rego admission policy, and the built-in Go twin
// only when OPA is unavailable or fails. A valid OPA verdict (including
// "scan") is final.
func (w *InstallWatcher) evaluateAdmission(ctx context.Context, input policy.AdmissionInput) *policy.AdmissionOutput {
	if w.policySource != nil {
		if prepared := w.policySource(); prepared != nil {
			if out, err := prepared.EvaluateAdmission(ctx, input); err == nil && out != nil {
				return out
			}
		}
		return policy.EvaluateAdmissionFallback(input)
	}
	if w.opa != nil {
		if out, err := w.opa.Evaluate(ctx, input); err == nil && out != nil {
			return out
		}
	}
	return policy.EvaluateAdmissionFallback(input)
}

// applyPostScanEnforcement takes the OPA verdict after scanning and executes
// the enforcement side-effects (block, quarantine, disable) that OPA cannot
// perform itself. It respects file_action and install_action from OPA output.
//
// The caller has already returned for block- and allow-listed items.
func (w *InstallWatcher) applyPostScanEnforcement(ctx context.Context, pe *enforce.PolicyEngine, out *policy.AdmissionOutput, evt InstallEvent, targetType string, result *scanner.ScanResult, scannerName string) {
	switch out.Verdict {
	case "clean":
		_ = w.logger.LogAction(string(audit.ActionInstallClean), evt.Path,
			fmt.Sprintf("type=%s scanner=%s", targetType, scannerName))
	case "rejected":
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s install_action=%s file_action=%s",
				targetType, result.MaxSeverity(), scannerName, out.InstallAction, out.FileAction))

		if w.takeActionFor(evt) {
			blockReason := fmt.Sprintf("auto-block: watch detected %s findings (scanner=%s)", result.MaxSeverity(), scannerName)
			// An operator restore keeps the files only while the install
			// block it left in place remains. Decide that before this scan
			// adds its own block: after an unblock + restore, the block below
			// is a fresh decision and the files must be quarantined again,
			// not retained under a "quarantined" record (GAP-1971).
			retainRestored := w.preserveRestoredBlockedAsset(evt)

			installAction := coalesce(out.InstallAction, "block")
			runtimeAction := coalesce(out.RuntimeAction, "allow")
			fileAction := coalesce(out.FileAction, "none")

			if installAction == "block" {
				_ = pe.Block(targetType, evt.Name, blockReason)
			}
			pe.SetSourcePath(targetType, evt.Name, evt.Path)

			enforcement := map[string]string{
				"source_path": evt.Path,
				"install":     installAction,
				"runtime":     runtimeAction,
				"file":        fileAction,
			}

			if fileAction == "quarantine" && !retainRestored {
				_ = pe.Quarantine(targetType, evt.Name, blockReason)
			}
			if runtimeAction == "block" {
				_ = pe.Disable(targetType, evt.Name, blockReason)
			}

			_ = w.logger.LogActionWithEnforcement(string(audit.ActionWatcherBlock), evt.Name,
				fmt.Sprintf("type=%s reason=%s", targetType, blockReason), enforcement)

			// Only a file action of quarantine moves the files. The block
			// shorthand (install block, runtime disable, file none) leaves
			// them where they are.
			if fileAction == "quarantine" {
				w.enforceBlockWith(ctx, evt, retainRestored)
			}
		}
	case "warning":
		_ = w.logger.LogAction(string(audit.ActionInstallWarning), evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, result.MaxSeverity(), scannerName))
	}
}

func (w *InstallWatcher) logAssetDiscovered(
	ctx context.Context,
	evt InstallEvent,
	details, reason string,
) {
	_ = w.logger.LogAssetDiscoveredCtx(ctx, evt.Path, details, audit.AssetLifecycleInput{
		AssetID: evt.Name, AssetType: string(evt.Type), TargetPath: evt.Path,
		Reason: reason, Initiator: "watcher",
	})
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func toVerdict(s string) Verdict {
	switch s {
	case "blocked":
		return VerdictBlocked
	case "allowed":
		return VerdictAllowed
	case "clean":
		return VerdictClean
	case "rejected":
		return VerdictRejected
	case "warning":
		return VerdictWarning
	default:
		return VerdictScanError
	}
}

func (w *InstallWatcher) scannerFor(evt InstallEvent) scanner.Scanner {
	// Each scanner kind gets its own resolved LLMConfig so
	// ``scanners.{skill,mcp}.llm`` overrides layered on top of the
	// global ``llm:`` block take effect. Resolving per-event (rather
	// than caching once at watcher startup) means a config reload is
	// picked up automatically on the next install.
	switch evt.Type {
	case InstallSkill:
		return w.withRulePackOverlay(scanner.NewSkillScannerFromLLM(
			w.cfg.Scanners.SkillScanner,
			w.cfg.ResolveLLM("scanners.skill"),
			w.cfg.CiscoAIDefense,
		), evt)
	case InstallMCP:
		return scanner.NewMCPScannerFromLLM(
			w.cfg.Scanners.MCPScanner,
			w.cfg.ResolveLLM("scanners.mcp"),
			w.cfg.CiscoAIDefense,
		)

	case InstallPlugin:
		return scanner.NewPluginScanner(w.cfg.Scanners.PluginScanner)
	default:
		return nil
	}
}

// defaultScanTimeout bounds a plugin or MCP scan, which have no timeout key.
const defaultScanTimeout = 5 * time.Minute

// scanTimeout is how long one watcher scan of evt may run. A skill scan
// follows scanners.skill_scanner.timeouts.scan_s, the bound the skill scanner
// puts on its own child process, so raising it for a large judge-on scan lets
// the install and every rescan finish; a fixed five minutes here made the key
// unable to stretch a scan. Plugin and MCP scans keep five minutes.
func (w *InstallWatcher) scanTimeout(evt InstallEvent) time.Duration {
	if evt.Type == InstallSkill {
		return time.Duration(w.cfg.Scanners.SkillScanner.ScanTimeoutSeconds()) * time.Second
	}
	return defaultScanTimeout
}

// withRulePackOverlay adds the connector's guardrail rule pack to a skill
// scan, as `defenseclaw skill scan` does, so a secret or an injection pattern
// in a skill's files is found at install and not only by the manual scan
// (GAP-0065). It returns inner when no pack applies.
func (w *InstallWatcher) withRulePackOverlay(inner scanner.Scanner, evt InstallEvent) scanner.Scanner {
	if w.rulePackSource == nil {
		return inner
	}
	return guardrail.NewArtifactOverlay(inner, w.rulePackSource(w.eventConnector(evt)))
}

// takeActionFor returns whether enforcement actions should be applied for the
// given event type, using the per-type gateway watcher config with a fallback
// to the legacy watch.auto_block flag.
func (w *InstallWatcher) takeActionFor(evt InstallEvent) bool {
	switch evt.Type {
	case InstallSkill:
		return w.cfg.Gateway.Watcher.Skill.TakeAction
	case InstallPlugin:
		return w.cfg.Gateway.Watcher.Plugin.TakeAction
	case InstallMCP:
		return w.cfg.Gateway.Watcher.MCP.TakeAction
	default:
		return w.cfg.Watch.AutoBlock
	}
}

func (w *InstallWatcher) enforceBlock(ctx context.Context, evt InstallEvent) {
	w.enforceBlockWith(ctx, evt, true)
}

// enforceBlockWith applies the block; honorRestore keeps the files of an
// operator-restored asset whose earlier install block still stands.
func (w *InstallWatcher) enforceBlockWith(ctx context.Context, evt InstallEvent, honorRestore bool) {
	switch evt.Type {
	case InstallMCP:
		// MCP servers have no filesystem artifact to quarantine. The sidecar's
		// handleMCPAdmission applies the block verdict to the connector's MCP
		// configuration from the admission result this watcher publishes.
	case InstallSkill, InstallPlugin:
		w.quarantineAssetWith(ctx, evt, honorRestore)
	}
}

// pluginCategoryQuarantineDir is the quarantine tree of plugins in a Hermes
// category folder (cli/defenseclaw/enforce/plugin_enforcer.py mirrors it).
const pluginCategoryQuarantineDir = "plugin-categories"

func (w *InstallWatcher) quarantineAsset(ctx context.Context, evt InstallEvent) {
	w.quarantineAssetWith(ctx, evt, true)
}

func (w *InstallWatcher) quarantineAssetWith(ctx context.Context, evt InstallEvent, honorRestore bool) {
	if w == nil || w.cfg == nil || w.store == nil {
		w.emitQuarantineFailure(ctx, evt, fmt.Errorf("watcher: quarantine provenance store is unavailable"))
		return
	}
	if honorRestore && w.preserveRestoredBlockedAsset(evt) {
		_ = w.logger.LogAction(string(audit.ActionWatcherBlock), evt.Path,
			fmt.Sprintf("type=%s restored physical files retained while install block remains", evt.Type))
		return
	}
	connector := w.eventConnector(evt)
	// The admission identity is connector-defined and may come from an asset
	// manifest (for example a Hermes SKILL.md name or a Claude plugin ID).  The
	// quarantine planner deliberately binds filesystem mutations to the exact
	// source basename.  Keep those identities separate so a valid manifest name
	// cannot weaken the path check or prevent an otherwise valid quarantine.
	physicalName := filepath.Base(filepath.Clean(evt.Path))
	plan, err := enforce.NewAssetQuarantinePlan(
		w.cfg.QuarantineDir, w.sourceRootsFor(evt.Type), evt.Type.String(),
		physicalName, connector, evt.Path,
	)
	if err != nil {
		w.emitQuarantineFailure(ctx, evt, err)
		return
	}
	if category, _, nested := strings.Cut(evt.Name, "/"); nested && evt.Type == InstallPlugin {
		// A plugin in a category folder keeps its category in quarantine, so
		// "plugin restore <category>/<name>" finds it and web/x and memx/x
		// don't share one slot (GAP-2464). It lives in its own tree
		// (plugin-categories/<connector>/<category>/<name>), not inside the
		// slot of a flat plugin named like the category, which "plugin
		// restore <category>" would otherwise restore with it (GAP-2470).
		plan.QuarantinePath = filepath.Join(
			plan.QuarantineRoot, pluginCategoryQuarantineDir, connector, filepath.Base(category), physicalName,
		)
	}
	record, err := w.store.CreateQuarantineRecord(ctx, audit.CreateQuarantineRecordInput{
		TargetType: evt.Type.String(), TargetName: evt.Name,
		OriginalPath: plan.SourcePath, QuarantinePath: plan.QuarantinePath,
		ContentHash: plan.ContentHash, Reason: "watcher enforcement",
		State: audit.QuarantineStatePending, OwnershipJSON: plan.OwnershipJSON,
		// The physical owner and global action scope are committed together so
		// either Go or Python restore clears the exact logical file decision.
		Connectors: []string{connector, ""},
	})
	if err != nil {
		w.emitQuarantineFailure(ctx, evt, err)
		return
	}
	if record.State == audit.QuarantineStateRestoring &&
		sameWatcherPath(record.RestorePath, plan.SourcePath) {
		matches, hashErr := enforce.AssetContentHashMatches(plan.SourcePath, record.ContentHash)
		if hashErr == nil && matches {
			_ = w.logger.LogAction(string(audit.ActionWatcherBlock), evt.Path,
				fmt.Sprintf("type=%s restore in progress; physical files retained", evt.Type))
			return
		}
	}
	if err := enforce.ExecuteAssetQuarantine(plan, record.ID); err != nil {
		// Roll back only an unmaterialized journal. A verified destination is
		// authoritative recovery data and must retain its pending provenance.
		if _, statErr := os.Lstat(plan.QuarantinePath); os.IsNotExist(statErr) {
			_ = w.store.DeleteQuarantineRecord(ctx, record.ID)
		}
		w.emitQuarantineFailure(ctx, evt, err)
		return
	}
	if err := w.store.UpdateQuarantineRecordState(
		ctx, record.ID, audit.QuarantineStateActive, "",
	); err != nil {
		// The pending write-ahead record is intentionally retained and can be
		// finalized or restored after restart.
		fmt.Fprintf(os.Stderr, "[watch] quarantine provenance remains pending for %s: %v\n", evt.Path, err)
	}
	w.recordQuarantineAudit(ctx, audit.ActionQuarantine, evt, plan.QuarantinePath)
}

// RestoreQuarantined restores one connector-owned watcher quarantine. The
// physical file action is cleared transactionally at completion, while an
// install block or runtime disable remains intact.
func (w *InstallWatcher) RestoreQuarantined(
	ctx context.Context,
	targetType, targetName, connector, restorePath string,
) error {
	if w == nil || w.cfg == nil || w.store == nil {
		return fmt.Errorf("watcher: quarantine provenance store is unavailable")
	}
	if ctx == nil {
		return fmt.Errorf("watcher: restore context is required")
	}
	targetType = strings.TrimSpace(targetType)
	targetName = strings.TrimSpace(targetName)
	connector = strings.TrimSpace(connector)
	if targetType != InstallSkill.String() && targetType != InstallPlugin.String() {
		return fmt.Errorf("watcher: unsupported restore target type %q", targetType)
	}
	records, err := w.store.ListQuarantineRecordsForConnector(
		ctx, targetType, targetName, connector,
	)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("watcher: %s %q is not quarantined for connector %q", targetType, targetName, connector)
	}
	if len(records) != 1 {
		return fmt.Errorf("watcher: restore is ambiguous for %s %q connector %q", targetType, targetName, connector)
	}
	record := records[0]
	requestedRestorePath := strings.TrimSpace(restorePath)
	boundRestorePath := strings.TrimSpace(record.RestorePath)
	if record.State == audit.QuarantineStateRestoring && boundRestorePath != "" {
		if requestedRestorePath == "" {
			restorePath = boundRestorePath
		} else if !sameWatcherPath(requestedRestorePath, boundRestorePath) {
			return fmt.Errorf(
				"watcher: explicit restore path does not match durable restoring destination",
			)
		} else {
			restorePath = requestedRestorePath
		}
	} else if requestedRestorePath == "" {
		restorePath = record.OriginalPath
	} else {
		restorePath = requestedRestorePath
	}
	if err := w.store.UpdateQuarantineRecordState(
		ctx, record.ID, audit.QuarantineStateRestoring, restorePath,
	); err != nil {
		return fmt.Errorf("watcher: journal quarantine restore: %w", err)
	}
	plan := enforce.AssetRestorePlan{
		RecordID: record.ID, TargetType: record.TargetType,
		TargetName:     filepath.Base(filepath.Clean(record.QuarantinePath)),
		QuarantineRoot: w.cfg.QuarantineDir, QuarantinePath: record.QuarantinePath,
		RestorePath: restorePath, AllowedRoots: w.sourceRootsFor(InstallType(record.TargetType)),
		ContentHash: record.ContentHash,
	}
	if err := enforce.ExecuteAssetRestore(plan); err != nil {
		if matches, matchErr := enforce.AssetContentHashMatches(
			record.QuarantinePath, record.ContentHash,
		); matchErr == nil && matches {
			_ = w.store.UpdateQuarantineRecordState(
				ctx, record.ID, audit.QuarantineStateActive, "",
			)
		}
		if w.logger != nil {
			_ = w.logger.RecordQuarantineActionMetric(ctx, "move_out", "error")
		}
		return fmt.Errorf("watcher: restore quarantined asset: %w", err)
	}
	if err := w.store.CompleteQuarantineRestore(ctx, record.ID, restorePath); err != nil {
		return fmt.Errorf("watcher: finalize quarantine restore: %w", err)
	}
	if w.logger != nil {
		_ = w.logger.RecordQuarantineActionMetric(ctx, "move_out", "ok")
		w.recordQuarantineAudit(ctx, audit.ActionRestore, InstallEvent{
			Type: InstallType(targetType), Name: targetName, Path: restorePath,
			Connector: connector, Timestamp: time.Now().UTC(),
		}, restorePath)
	}
	return nil
}

func (w *InstallWatcher) sourceRootsFor(targetType InstallType) []string {
	switch targetType {
	case InstallSkill:
		return w.skillDirs
	case InstallPlugin:
		return w.pluginDirs
	default:
		return nil
	}
}

func (w *InstallWatcher) preserveRestoredBlockedAsset(evt InstallEvent) bool {
	if w == nil || w.store == nil {
		return false
	}
	connector := w.eventConnector(evt)
	pe := enforce.NewPolicyEngine(w.store)
	blocked, err := pe.JournalInstallBlocked(evt.Type.String(), evt.Name, connector)
	if err != nil || !blocked {
		return false
	}
	connectors := []string{connector}
	if connector != "" {
		connectors = append(connectors, "")
	}
	// A restore clears the file action in every scope it owned. A file
	// action set in any scope since then is a later quarantine decision (for
	// example a re-scan block after unblock + restore), so the restored-files
	// exception no longer applies and a re-added copy is quarantined
	// (GAP-1971).
	restored := false
	for _, scope := range connectors {
		entry, err := w.store.GetActionForConnector(evt.Type.String(), evt.Name, scope)
		if err != nil || entry == nil {
			continue
		}
		if entry.Actions.File != "" {
			return false
		}
		if entry.SourcePath != "" && sameWatcherPath(entry.SourcePath, evt.Path) {
			restored = true
		}
	}
	return restored
}

// queueExistingClaudePlugins queues the <marketplace>/<plugin>/<version>
// folders that already exist below a new folder of Claude Code's plugin
// cache. A marketplace or plugin tree created in one go (a copy, an
// extracted archive, mkdir -p) has its version folder in place before the
// watch on its parent exists, so no later create event names it and the
// plugin never reached admission until the hourly rescan, which only
// baselines it. depth is how far below the cache root dir sits (1 =
// marketplace, 2 = plugin). The Secure Client deployment keeps the watcher it
// had.
func (w *InstallWatcher) queueExistingClaudePlugins(ctx context.Context, dir string, depth int) {
	if w.secureClientActive() {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		child := filepath.Join(dir, entry.Name())
		if depth+1 < 3 {
			w.queueExistingClaudePlugins(ctx, child, depth+1)
			continue
		}
		w.recordWatcherEvent(ctx, "create", w.classifyEvent(child).Type.String(), "")
		w.mu.Lock()
		if _, exists := w.pending[child]; !exists {
			w.pending[child] = time.Now()
		}
		w.mu.Unlock()
	}
}

func (w *InstallWatcher) claudeCacheDepth(path string) (int, bool) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return 0, false
	}
	for _, root := range w.pluginDirs {
		rootAbs, absErr := filepath.Abs(root)
		if absErr != nil || !strings.EqualFold(filepath.Base(rootAbs), "cache") {
			continue
		}
		relative, relErr := filepath.Rel(rootAbs, pathAbs)
		if relErr != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		return len(strings.FieldsFunc(relative, func(r rune) bool {
			return r == '/' || r == '\\'
		})), true
	}
	return 0, false
}

func sameWatcherPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(strings.TrimSpace(left))
	rightAbs, rightErr := filepath.Abs(strings.TrimSpace(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftAbs = filepath.Clean(leftAbs)
	rightAbs = filepath.Clean(rightAbs)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftAbs, rightAbs)
	}
	return leftAbs == rightAbs
}

func watcherPathAtOrBelow(path, root string) bool {
	pathAbs, pathErr := filepath.Abs(filepath.Clean(path))
	rootAbs, rootErr := filepath.Abs(filepath.Clean(root))
	if pathErr != nil || rootErr != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

// emitQuarantineFailure reports an asset the verdict blocked but the watcher
// could not move: it stays in place, so besides the log line and the metric
// the audit log records an enforcement failure the administrator can find
// (GAP-0133).
func (w *InstallWatcher) emitQuarantineFailure(ctx context.Context, evt InstallEvent, err error) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordQuarantineActionMetric(ctx, "move_in", "error")
		_ = w.logger.LogEventCtx(ctx, audit.Event{
			Action:   string(audit.ActionWatcherBlock),
			Target:   evt.Path,
			Actor:    "defenseclaw",
			Details:  fmt.Sprintf("type=%s quarantine failed, the blocked asset stays in place: %v", evt.Type, err),
			Severity: "HIGH",
		})
	}
	fmt.Fprintf(os.Stderr, "[watch] quarantine %s: %v\n", evt.Path, err)
}

func (w *InstallWatcher) recordQuarantineAudit(ctx context.Context, action audit.Action, evt InstallEvent, destPath string) {
	event := audit.Event{
		Action:   string(action),
		Target:   evt.Path,
		Actor:    "defenseclaw",
		Details:  fmt.Sprintf("dest=%s", destPath),
		Severity: "INFO",
	}
	if action != audit.ActionQuarantine {
		_ = w.logger.LogEventCtx(ctx, event)
		return
	}
	_ = w.logger.LogEnforcementQuarantineApplied(ctx, event, audit.EnforcementQuarantineAppliedInput{
		EnforcementID:   uuid.NewString(),
		RequestedAction: "quarantine",
		EffectiveAction: "quarantine",
		Initiator:       "defenseclaw",
		ResultingState:  "quarantined",
		AssetID:         evt.Name,
		AssetType:       evt.Type.String(),
		SourcePath:      evt.Path,
		DestinationPath: destPath,
	})
}

// isDirectChildDir returns true if path is a directory and a direct child
// of one of the watched skill or MCP directories. Files and nested
// subdirectories inside a skill are ignored — a skill is always a top-level
// directory under a skill dir.
func (w *InstallWatcher) isDirectChildDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}

	parent := filepath.Dir(path)
	parentAbs, _ := filepath.Abs(parent)

	for _, dir := range w.skillDirs {
		dirAbs, _ := filepath.Abs(dir)
		if parentAbs == dirAbs {
			if isBundledSkillWatchPath(path) {
				return false
			}
			return true
		}
	}
	for _, dir := range w.pluginDirs {
		dirAbs, _ := filepath.Abs(dir)
		if parentAbs == dirAbs {
			return !skipPluginChildDir(filepath.Base(path))
		}
	}
	if w.connectorForPath(path) == "claudecode" {
		if depth, inside := w.claudeCacheDepth(path); inside {
			return depth == 3
		}
	}
	return false
}

func isBundledSkillWatchPath(path string) bool {
	if enforce.IsBundledSkillPath(path) {
		return true
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && enforce.IsBundledSkillPath(resolved)
}

func (w *InstallWatcher) recordAdmission(ctx context.Context, decision, targetType string) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordAdmissionDecisionMetric(ctx, decision, targetType, "watcher")
	}
}

func (w *InstallWatcher) recordWatcherEvent(
	ctx context.Context,
	eventType, targetType, connector string,
) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordWatcherEventMetric(ctx, eventType, targetType, connector)
	}
}

func (w *InstallWatcher) recordWatcherError(ctx context.Context) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordWatcherErrorMetric(ctx)
	}
}

func (w *InstallWatcher) recordBlockSLO(ctx context.Context, targetType string, latencyMS float64) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordBlockSLOMetric(ctx, targetType, latencyMS)
	}
}

func (w *InstallWatcher) recordScanError(
	ctx context.Context,
	scannerName, targetType, errorType string,
) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordWatcherScanErrorMetric(ctx, scannerName, targetType, errorType)
	}
}

// logScanID logs an admission scan and returns its scan id, or "" when the
// scan row was not written.
func (w *InstallWatcher) logScanID(ctx context.Context, evt InstallEvent, result *scanner.ScanResult, verdict string) string {
	if err := w.logScan(ctx, evt, result, verdict); err != nil {
		return ""
	}
	return result.ScanID
}

func (w *InstallWatcher) logScan(
	ctx context.Context,
	evt InstallEvent,
	result *scanner.ScanResult,
	verdict string,
) error {
	if w == nil || w.logger == nil {
		return fmt.Errorf("watcher: v8 scan logger is unavailable")
	}
	return w.logger.LogScanWithCorrelation(
		ctx, result, verdict,
		watcherScanCorrelation(ctx, "", w.eventConnector(evt)),
	)
}

func watcherScanCorrelation(
	ctx context.Context,
	runID, connector string,
) audit.ScanCorrelation {
	envelope := audit.EnvelopeFromContext(ctx)
	if runID == "" {
		runID = envelope.RunID
	}
	correlation := audit.ScanCorrelation{
		RunID: runID, RequestID: envelope.RequestID, SessionID: envelope.SessionID,
		TraceID: envelope.TraceID, AgentID: envelope.AgentID, AgentName: envelope.AgentName,
		AgentInstanceID: envelope.AgentInstanceID, Connector: connector,
		EvaluationID: watcherAdmissionEvaluationID(ctx),
	}
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		if correlation.TraceID == "" {
			correlation.TraceID = spanContext.TraceID().String()
			correlation.SpanID = spanContext.SpanID().String()
		}
		if correlation.TraceID == spanContext.TraceID().String() && correlation.SpanID == "" {
			correlation.SpanID = spanContext.SpanID().String()
		}
	}
	return correlation
}

func watcherConnectorName(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if strings.TrimSpace(cfg.Guardrail.Connector) != "" {
		return strings.ToLower(strings.TrimSpace(cfg.Guardrail.Connector))
	}
	return strings.ToLower(strings.TrimSpace(string(cfg.Claw.Mode)))
}

func classifyWatcherScanError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found") || strings.Contains(msg, "executable file not found"):
		return "not_found"
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "timeout"):
		return "timeout"
	case strings.Contains(msg, "parse") || strings.Contains(msg, "unmarshal") || strings.Contains(msg, "json"):
		return "parse"
	default:
		return "crash"
	}
}

func toFindingInputs(findings []scanner.Finding) []policy.FindingInput {
	if len(findings) == 0 {
		return nil
	}
	out := make([]policy.FindingInput, 0, len(findings))
	for _, f := range findings {
		out = append(out, policy.FindingInput{
			Severity: string(f.Severity),
			Scanner:  f.Scanner,
			Title:    f.Title,
		})
	}
	return out
}

// agentOwnedDirNames are folders an agent's own installer creates and expects
// to be absent: the Hermes installer refuses an existing ~/.hermes/hermes-agent
// that is not its git checkout (GAP-2354).
var agentOwnedDirNames = map[string]struct{}{"hermes-agent": {}}

// createsAgentOwnedDir reports whether creating dir would also create one of
// agentOwnedDirNames (dir itself or a missing parent).
func createsAgentOwnedDir(dir string) bool {
	current, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	for {
		if _, err := os.Lstat(current); !errors.Is(err, fs.ErrNotExist) {
			return false
		}
		if _, owned := agentOwnedDirNames[strings.ToLower(filepath.Base(current))]; owned {
			return true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
		current = parent
	}
}

// ensureAndWatch creates dir when it is missing and watches it. It returns
// the absolute paths of the folders it created: dir and any missing parents.
func ensureAndWatch(fsw *fsnotify.Watcher, dir string) ([]string, error) {
	var created []string
	if current, err := filepath.Abs(dir); err == nil {
		for {
			if _, err := os.Lstat(current); !errors.Is(err, fs.ErrNotExist) {
				break
			}
			created = append(created, current)
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}

	if err := fsw.Add(dir); err != nil {
		return created, fmt.Errorf("watch: %w", err)
	}

	return created, nil
}

func addClaudeCacheWatches(
	fsw *fsnotify.Watcher,
	root string,
	watched map[string]struct{},
) {
	addDirWatches(fsw, root, 2, watched)
}

// forgetDirWatches drops the watches of path and the folders below it once
// path was moved (to quarantine) or removed. fsnotify drops the watch of the
// moved folder itself, but watchedDirs kept its key, so addDirWatches skipped
// a folder re-created at the same path and nothing added to it reached
// admission (GAP-2469). Watches of sub-folders that moved along are removed
// too, so events inside quarantine aren't reported under the old path.
func forgetDirWatches(fsw *fsnotify.Watcher, path string, watched map[string]struct{}) {
	key := strings.ToLower(filepath.Clean(path))
	if _, ok := watched[key]; !ok {
		return
	}
	below := func(p string) bool {
		p = strings.ToLower(filepath.Clean(p))
		return p == key || strings.HasPrefix(p, key+string(filepath.Separator))
	}
	for k := range watched {
		if below(k) {
			delete(watched, k)
		}
	}
	for _, p := range fsw.WatchList() {
		if below(p) {
			_ = fsw.Remove(p)
		}
	}
}

// addDirWatches watches root and its real (non-symlink) subfolders down to
// maxDepth levels below it.
func addDirWatches(
	fsw *fsnotify.Watcher,
	root string,
	maxDepth int,
	watched map[string]struct{},
) {
	root = filepath.Clean(root)
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return fs.SkipAll
			}
			return fs.SkipDir
		}
		if !entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fs.SkipDir
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fs.SkipDir
		}
		depth := 0
		if relative != "." {
			depth = len(strings.FieldsFunc(relative, func(r rune) bool {
				return r == '/' || r == '\\'
			}))
		}
		if depth > maxDepth {
			return fs.SkipDir
		}
		key := strings.ToLower(filepath.Clean(path))
		if _, exists := watched[key]; !exists {
			if addErr := fsw.Add(path); addErr == nil {
				watched[key] = struct{}{}
			}
		}
		return nil
	})
}
