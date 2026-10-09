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
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
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
	// readmitReason names why the rescan admits a known target again; the
	// watcher-block row carries it.
	readmitReason string
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
	// Interrupted is a scan the watcher's own stop cut off: nothing was
	// decided, no baseline is kept, and the next start admits the asset.
	Interrupted bool
	// Unenforced is a rejection decided while take_action was off for the
	// type, so nothing was blocked or quarantined. Its rescan baseline keeps
	// a mark, and admission runs again once take_action is on (GAP-0774).
	Unenforced bool
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
	// lastDenyLists is the denied skill and plugin lists the previous rescan
	// cycle applied to installed assets (rescan goroutine only).
	lastDenyLists string
	// startupAdmitRoots are the skill and plugin roots that already held
	// baselines when the startup rescan began (rescan goroutine only).
	startupAdmitRoots map[InstallType][]string
	// newRoots are watch roots the gateway did not watch before this
	// watcher started (AdmitNewRootsAtStartup); the startup rescan admits
	// what they hold.
	newRoots []string
	// rescanFailureLogged keeps the targets whose failed rescan scan was
	// audited, so a scanner that stays down writes one row per target.
	rescanFailureMu     sync.Mutex
	rescanFailureLogged map[string]bool
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
	// (empty or category folders, GAP-2449) and skill folders without a
	// markdown file yet (GAP-0900); they are watched for what lands in them,
	// and addWatch adds such a watch. Both are used on the Run goroutine only.
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

	// admissionPolicySource reads one generation for config, prepared policy,
	// and its stamp. A post-scan decision takes a fresh snapshot.
	admissionPolicySource func() AdmissionPolicySnapshot

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
	// assetOwners names the account of each enrolled home, longest home
	// first (SetAssetOwners).
	assetOwners []AssetOwner

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
	// mcpClaims are the MCP servers (event paths) that loop or the rescan
	// cycle is handling: the other one leaves a claimed server alone, so a
	// server is admitted once and its admission never waits for the scan of
	// another server (GAP-0254).
	mcpClaimMu sync.Mutex
	mcpClaims  map[string]bool
	// mcpStartup are the MCP servers the first rescan cycle listed: that
	// cycle records their baselines, so discovery skips them until it ends
	// and admits every other server at once (GAP-0254).
	mcpStartupMu     sync.Mutex
	mcpStartup       map[string]bool
	mcpStartupListed atomic.Bool

	// binaryVersions caches each scanner binary's probed --version and file identity.
	binaryVersions sync.Map

	// state publishes the assets awaiting admission (AdmissionStateFile).
	state *admissionState
	// inFlight are the queued paths an admission worker holds (under mu);
	// an event for one waits in pending until that admission ends.
	inFlight map[string]bool
	// liveSlots and startupSlots bound the concurrent admissions of the
	// live watcher and of the startup rescan; admissions tracks them.
	liveSlots    chan struct{}
	startupSlots chan struct{}
	admissions   sync.WaitGroup
	// admitMu serializes onAdmit, which admission workers call.
	admitMu sync.Mutex
	// movedOut are the paths whose asset admission quarantined or whose link
	// it removed: they get no rescan baseline (forgetMovedAsset).
	movedOut sync.Map
	// admissionNotes are what an admission running on a path could not
	// finish (an AdmissionIssue), for settleAdmissionIssue.
	admissionNotes sync.Map
	// fpMu guards a rescan cycle's fingerprint cache.
	fpMu sync.Mutex

	// pollMCP has Run look for MCP servers added outside `mcp set` every
	// mcpDiscoveryInterval (SetMCPDiscoveryPoll); firstCycleDone says the
	// first rescan cycle ended (mcpStartup applies until then).
	pollMCP        bool
	firstCycleDone atomic.Bool
}

type rootConnector struct {
	root      string
	connector string
}

// AdmitNewRootsAtStartup names watch roots that appeared after the gateway
// started watching (an enrolled user created ~/.claude/skills): the startup
// rescan runs install admission for what they hold, as the live watcher does
// for an install, instead of only recording a baseline. Before, a skill
// copied in with its folder was baselined, so with the scanner runtime
// missing it was neither blocked nor audited (GAP-0571). Call before Run.
func (w *InstallWatcher) AdmitNewRootsAtStartup(roots []string) {
	w.newRoots = append([]string(nil), roots...)
}

// AssetOwner is the account whose home holds watched assets.
type AssetOwner struct {
	Home, ID, IDKind, Name string
}

// SetAssetOwners names the account of each enrolled home. A managed gateway
// watches every enrolled user's folders, so its scan, scan-finding and
// quarantine rows name the user whose asset it was (GAP-0575). Call it
// before Run.
func (w *InstallWatcher) SetAssetOwners(owners []AssetOwner) {
	w.assetOwners = w.assetOwners[:0]
	for _, owner := range owners {
		if home := strings.TrimSpace(owner.Home); home != "" {
			owner.Home = filepath.Clean(home)
			w.assetOwners = append(w.assetOwners, owner)
		}
	}
	sort.Slice(w.assetOwners, func(i, j int) bool { return len(w.assetOwners[i].Home) > len(w.assetOwners[j].Home) })
}

// ownerOf is the account whose home holds path.
func (w *InstallWatcher) ownerOf(path string) (AssetOwner, bool) {
	if w == nil || w.secureClientActive() {
		return AssetOwner{}, false
	}
	for _, owner := range w.assetOwners {
		if watcherPathAtOrBelow(path, owner.Home) {
			return owner, true
		}
	}
	return AssetOwner{}, false
}

// ownedScanCorrelation adds the asset's owner and the judge model of the
// scan to a watcher scan correlation (GAP-0575).
func (w *InstallWatcher) ownedScanCorrelation(correlation audit.ScanCorrelation, result *scanner.ScanResult) audit.ScanCorrelation {
	if w == nil || result == nil || w.secureClientActive() {
		return correlation
	}
	correlation.JudgeModel = result.JudgeModel
	if owner, ok := w.ownerOf(result.Target); ok {
		correlation.UserID, correlation.UserIDKind, correlation.UserName = owner.ID, owner.IDKind, owner.Name
	}
	return correlation
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

		state:        newAdmissionState(cfg.DataDir),
		inFlight:     make(map[string]bool),
		liveSlots:    make(chan struct{}, liveAdmissionWorkers),
		startupSlots: make(chan struct{}, startupAdmissionWorkers),
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
// A server the rescan cycle is handling is left to it; a server whose
// baseline could not be read is queued again for the next discovery. Both
// say so in gateway.log, so a missed admission is never silent.
func (w *InstallWatcher) admitAddedMCPServers(ctx context.Context) {
	w.addedMCPMu.Lock()
	names := w.addedMCP
	w.addedMCP = nil
	w.addedMCPMu.Unlock()
	servers, err := w.readMCPServers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watch] list mcp servers for admission: %v\n", err)
		return
	}
	for _, server := range servers {
		if ctx.Err() != nil {
			return
		}
		if !names[server.Name] || server.Bundled {
			continue
		}
		evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(server), Connector: server.Connector, Timestamp: time.Now().UTC()}
		if !w.claimMCP(evt.Path) {
			continue // the rescan cycle is admitting or scanning it
		}
		w.admitAddedMCPServer(ctx, evt)
		w.releaseMCP(evt.Path)
	}
}

func (w *InstallWatcher) admitAddedMCPServer(ctx context.Context, evt InstallEvent) {
	_, err := w.store.GetTargetSnapshot(string(evt.Type), evt.Path)
	if err == nil {
		return // admitted or baselined already
	}
	if !errors.Is(err, sql.ErrNoRows) {
		fmt.Fprintf(os.Stderr, "[watch] mcp %s was added; its baseline could not be read, retrying: %v\n", evt.Name, err)
		w.queueAddedMCP(evt.Name)
		return
	}
	snap, err := w.snapshotForEvent(evt)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "[watch] mcp %s was added; reading its definition failed: %v\n", evt.Name, err)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "[watch] mcp %s was added; running install admission\n", evt.Name)
	res := w.runAdmission(ctx, evt)
	w.notifyAdmission(res)
	if !res.Interrupted {
		w.persistSnapshot(evt, snap, res.ScanID, w.admissionFingerprint(res, w.cachedFingerprint(evt, nil)))
	}
}

// queueAddedMCP queues name for the next admission pass without waking it.
func (w *InstallWatcher) queueAddedMCP(name string) {
	w.addedMCPMu.Lock()
	if w.addedMCP == nil {
		w.addedMCP = map[string]bool{}
	}
	w.addedMCP[name] = true
	w.addedMCPMu.Unlock()
}

// claimMCP marks the MCP server at path as handled by the caller; it fails
// while another admission or the rescan cycle holds it.
func (w *InstallWatcher) claimMCP(path string) bool {
	w.mcpClaimMu.Lock()
	defer w.mcpClaimMu.Unlock()
	if w.mcpClaims[path] {
		return false
	}
	if w.mcpClaims == nil {
		w.mcpClaims = map[string]bool{}
	}
	w.mcpClaims[path] = true
	return true
}

func (w *InstallWatcher) releaseMCP(path string) {
	w.mcpClaimMu.Lock()
	delete(w.mcpClaims, path)
	w.mcpClaimMu.Unlock()
}

// recordStartupMCP keeps the MCP servers the first rescan cycle lists and
// lets discovery start at once instead of after that cycle (GAP-0254).
func (w *InstallWatcher) recordStartupMCP(targets []InstallEvent) {
	w.mcpStartupMu.Lock()
	w.mcpStartup = map[string]bool{}
	for _, evt := range targets {
		if evt.Type == InstallMCP {
			w.mcpStartup[evt.Path] = true
		}
	}
	w.mcpStartupMu.Unlock()
	w.mcpStartupListed.Store(true)
}

func (w *InstallWatcher) listedAtStartup(path string) bool {
	w.mcpStartupMu.Lock()
	defer w.mcpStartupMu.Unlock()
	return w.mcpStartup[path]
}

// mcpDiscoveryInterval is how often a per-user watcher looks for MCP
// servers added outside `defenseclaw mcp set`.
var mcpDiscoveryInterval = 30 * time.Second

// SetMCPDiscoveryPoll has the watcher admit, within mcpDiscoveryInterval, an
// MCP server added by the agent's own commands (claude mcp add, an edited
// .mcp.json) instead of at the next hourly rescan (GAP-0405). Call it after
// SetMCPServerSource and before Run.
func (w *InstallWatcher) SetMCPDiscoveryPoll(enabled bool) {
	w.pollMCP = enabled && w.admitNewMCP
}

func (w *InstallWatcher) mcpDiscoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(mcpDiscoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.discoverAddedMCPServers()
		}
	}
}

// DiscoverAddedMCPServers admits now every MCP server without a baseline. A
// managed gateway calls it when its enrolled users servers change.
func (w *InstallWatcher) DiscoverAddedMCPServers() {
	if w == nil || !w.admitNewMCP {
		return
	}
	w.discoverAddedMCPServers()
}

// discoverAddedMCPServers queues for admission the MCP servers that have no
// baseline yet. It starts once the first rescan cycle listed the existing
// servers, which that cycle baselines; it does not wait for the cycle to
// end, which after an upgrade rescans every skill for many minutes
// (GAP-0254).
func (w *InstallWatcher) discoverAddedMCPServers() {
	firstCycle := !w.firstCycleDone.Load()
	if (firstCycle && !w.mcpStartupListed.Load()) || w.store == nil {
		return
	}
	servers, err := w.readMCPServers()
	if err != nil {
		return
	}
	var added []string
	for _, server := range servers {
		if strings.TrimSpace(server.Name) == "" || server.Bundled {
			continue
		}
		path := MCPEventPath(server)
		if firstCycle && w.listedAtStartup(path) {
			continue
		}
		if _, err := w.store.GetTargetSnapshot(string(InstallMCP), path); err != nil {
			// A read error other than no rows is retried by admission,
			// which says so.
			added = append(added, server.Name)
		}
	}
	w.AdmitAddedMCPServers(added)
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

// AdmissionPolicySnapshot is the policy used for one admission decision.
type AdmissionPolicySnapshot struct {
	Config     *config.Config
	Prepared   *policy.Prepared
	Digest     observability.Optional[string]
	Generation observability.Optional[int64]
}

// SetAdmissionPolicySource binds one atomic generation read for admission.
func (w *InstallWatcher) SetAdmissionPolicySource(source func() AdmissionPolicySnapshot) {
	w.admissionPolicySource = source
}

func (w *InstallWatcher) admissionPolicySnapshot() AdmissionPolicySnapshot {
	if w.admissionPolicySource != nil {
		return w.admissionPolicySource()
	}
	snapshot := AdmissionPolicySnapshot{Config: w.liveConfig()}
	if w.policySource != nil {
		snapshot.Prepared = w.policySource()
	}
	if w.policyStamp != nil {
		snapshot.Digest, snapshot.Generation = w.policyStamp()
	}
	return snapshot
}

func (w *InstallWatcher) evaluateAdmissionSnapshot(ctx context.Context, input policy.AdmissionInput, snapshot AdmissionPolicySnapshot) *policy.AdmissionOutput {
	if w.admissionPolicySource == nil {
		return w.evaluateAdmission(ctx, input)
	}
	if snapshot.Prepared != nil {
		if out, err := snapshot.Prepared.EvaluateAdmission(ctx, input); err == nil && out != nil {
			return out
		}
	}
	return policy.EvaluateAdmissionFallback(input)
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

// scanConfig is the current scanner configuration. Secure Client retains its
// startup scanner settings, as in the pre-v9 profile.
func (w *InstallWatcher) scanConfig() *config.Config {
	if w.cfg != nil && w.cfg.SecureClientIntegration() {
		return w.cfg
	}
	return w.liveConfig()
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
			w.watchIncompleteSkillFolders(dir)
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
	if w.pollMCP {
		if !w.cfg.Watch.RescanEnabled {
			w.firstCycleDone.Store(true)
		}
		go w.mcpDiscoveryLoop(ctx)
	}

	ticker := time.NewTicker(w.debounce)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// In-flight admissions see the stop and end without a verdict
			// (GAP-0335); wait for them before the store goes away.
			w.admissions.Wait()
			w.state.reset()
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
					if w.inClaudePluginStaging(event.Name, 0) {
						continue
					}
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
			w.queuePending(queued)

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
			// Admit again what a failed scan or quarantine left in place.
			for _, issue := range w.state.dueIssues(time.Now(), AdmissionUnscanned, AdmissionNotQuarantined) {
				w.queuePending(issue.Path)
			}
			w.processPending(ctx)
		}
	}
}

// queuePending queues path for admission after the debounce and shows it
// as pending (AdmissionStateFile).
func (w *InstallWatcher) queuePending(path string) {
	w.mu.Lock()
	_, exists := w.pending[path]
	if !exists {
		w.pending[path] = time.Now()
	}
	w.mu.Unlock()
	if !exists {
		w.state.set(w.classifyEvent(path), AdmissionPending)
	}
}

// processPending hands each debounced path to an admission worker. At most
// liveAdmissionWorkers scans run at once, and the Run loop keeps reading
// events while they do: a bulk drop of skills used to be admitted one at a
// time, about one a minute with the judge, each skill loaded and unscanned
// until its turn (GAP-0341).
func (w *InstallWatcher) processPending(ctx context.Context) {
	w.mu.Lock()
	now := time.Now()
	var ready []string
	for path, firstSeen := range w.pending {
		if w.inFlight[path] {
			continue // admitted again once the running admission ends
		}
		if now.Sub(firstSeen) >= w.debounce {
			ready = append(ready, path)
		}
	}
	for _, p := range ready {
		delete(w.pending, p)
		w.inFlight[p] = true
	}
	w.mu.Unlock()

	for _, path := range ready {
		if _, err := os.Stat(addressablePath(path)); err != nil && !w.admitsLinkedAsset(path) {
			w.endAdmission(path)
			continue
		}
		events := w.pendingInstallEvents(path) // Run goroutine state
		w.admissions.Add(1)
		go func() {
			defer w.admissions.Done()
			defer w.endAdmission(path)
			select {
			case w.liveSlots <- struct{}{}:
			case <-ctx.Done():
				return // no baseline: the next start admits it
			}
			defer func() { <-w.liveSlots }()
			for _, evt := range events {
				if ctx.Err() != nil {
					return
				}
				w.state.set(evt, AdmissionScanning)
				snap := w.admissionSnapshot(evt)
				result := w.runAdmission(ctx, evt)
				w.recordAdmissionBaseline(evt, snap, result)
				w.state.clear(evt.Path)
				w.notifyAdmission(result)
			}
		}()
	}
}

// endAdmission releases a queued path an admission worker held.
func (w *InstallWatcher) endAdmission(path string) {
	w.mu.Lock()
	delete(w.inFlight, path)
	w.mu.Unlock()
	w.state.clear(path)
}

// waitAdmissions waits for the admissions processPending started.
func (w *InstallWatcher) waitAdmissions() { w.admissions.Wait() }

// notifyAdmission reports an admission result; workers call it one at a time.
func (w *InstallWatcher) notifyAdmission(res AdmissionResult) {
	if w.onAdmit == nil {
		return
	}
	w.admitMu.Lock()
	defer w.admitMu.Unlock()
	w.onAdmit(res)
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
	if fallback.Type == InstallSkill && w.isDirectChildDir(path) {
		if skillFolderIncomplete(path) {
			w.waitForPluginFolder(path)
			return []InstallEvent{}
		}
		delete(w.pluginWaiting, filepath.Clean(path))
	}
	return []InstallEvent{fallback}
}

// skillFolderIncomplete reports whether a folder in a skill root holds nothing
// an agent or skill-scanner loads as a skill yet: no SKILL.md and no other
// markdown file at its top. A folder just made with mkdir, being filled in,
// used to be admitted at once, refused by the scanner ("No SKILL.md and no .md
// files found") and quarantined fail-closed while the user was creating it
// (GAP-0900); the watcher waits on it instead and admits it, with everything
// already in it, once a markdown file lands. A link, or a folder that cannot
// be read, is not incomplete: it is admitted and fails closed as before
// (GAP-0394).
func skillFolderIncomplete(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
			return false
		}
	}
	return true
}

// watchIncompleteSkillFolders waits on the skill folders in root that have no
// markdown file yet when the watcher starts, so a SKILL.md written into one
// later reaches admission (live-created ones are waited on by
// pendingInstallEvents). Hermes roots hold category folders and keep their own
// discovery.
func (w *InstallWatcher) watchIncompleteSkillFolders(root string) {
	if discover, _ := hermesSkillsDiscover(root); discover != nil {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || isBundledSkillWatchPath(path) {
			continue
		}
		if _, synced := w.claudeSyncedDepth(path); synced {
			continue
		}
		if skillFolderIncomplete(path) {
			w.waitForPluginFolder(path)
		}
	}
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
	return watcherConnectorName(w.scanConfig())
}

// runAdmission applies the full admission gate: block → allow → scan.
// When the OPA engine is available it delegates the verdict decision to
// Rego policy; otherwise it falls back to the built-in Go logic.
func (w *InstallWatcher) runAdmission(ctx context.Context, evt InstallEvent) (res AdmissionResult) {
	w.admissionNotes.Delete(evt.Path)
	defer func() { w.settleAdmissionIssue(evt, res) }()
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

	targetType := string(evt.Type)
	policyID := enforce.PolicyStableID(w.cfg.PolicyDir)
	decisionPolicy := w.admissionPolicySnapshot()
	ctx, admissionTrace := w.startAdmissionTraceV8(ctx, evt, targetType, policyID, decisionPolicy)
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

	cfg := decisionPolicy.Config
	connector := w.eventConnector(evt)
	assetDecision := cfg.EvaluateAssetPolicy(w.withMCPDefinition(cfg, evt, config.AssetPolicyInput{
		TargetType:     targetType,
		Name:           evt.Name,
		DeclaredNames:  declaredAssetNames(cfg, evt),
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
	out := w.evaluateAdmissionSnapshot(ctx, input, decisionPolicy)
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
		w.releaseAllowListed(evt, out.Reason)
		if evt.Type == InstallMCP {
			// Admitted without the scan whose failure blocked it: an allow
			// rule or scan_on_install false (GAP-0910).
			w.releaseScanFailureBlock(evt, targetType)
		}
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
	if err == nil && !w.secureClientActive() {
		err = scanner.JudgeFailure(result)
	}
	if err != nil && ctx.Err() == nil && !w.secureClientActive() {
		if retry, unreadable := w.readableAfterGrant(evt); retry {
			retryCtx, cancelRetry := context.WithTimeout(ctx, w.scanTimeout(evt))
			defer cancelRetry()
			if result, err = s.Scan(retryCtx, w.scanTargetFor(evt)); err == nil {
				err = scanner.JudgeFailure(result)
			}
		} else if unreadable != "" {
			err = fmt.Errorf("%s: %w", unreadable, err)
		}
	}
	if err != nil && ctx.Err() != nil && !w.secureClientActive() {
		// The watcher itself is stopping (a config reload restarts it, or
		// the gateway stops), not the scanner failing: the scan was cut off
		// with nothing known about the asset. It is not blocked, and with no
		// baseline the next start admits it (GAP-0335). A scan that times
		// out or fails while the watcher runs still fails closed below.
		_ = w.logger.LogAction(string(audit.ActionInstallScanError), evt.Path,
			fmt.Sprintf("type=%s scanner=%s error=interrupted: the watcher is stopping", targetType, s.Name()))
		fmt.Fprintf(os.Stderr, "[watch] %s %s: scan interrupted because the watcher is stopping; the next start admits it\n",
			evt.Type, evt.Name)
		w.recordAdmission(ctx, "scan-error", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictScanError, Interrupted: true,
			Reason: "scan interrupted: the watcher is stopping; the next start admits it"}
		return res
	}
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
		reason := scanFailureReason + err.Error()
		secureClient := w.secureClientActive()
		if secureClient {
			w.enforceBlock(ctx, evt)
		} else {
			// Block and disable it at runtime as a rejected verdict does,
			// before the move that may fail: a blocked MCP server stayed
			// callable and a skill the gateway could not read or move
			// still loaded (GAP-0662, GAP-0825).
			w.recordScanFailureBlock(evt, targetType, reason)
			// The reason goes on the quarantine record (skill info) and
			// in an alert, not only in gateway.log (GAP-0376).
			w.enforceBlockWith(ctx, evt, true, reason)
			_ = w.logger.LogEventCtx(ctx, audit.Event{
				Action:   string(audit.ActionWatcherBlock),
				Target:   evt.Path,
				Actor:    "defenseclaw",
				Details:  fmt.Sprintf("type=%s scan failed, blocked: %s", targetType, reason),
				Severity: "HIGH",
			})
		}
		_ = w.logger.LogAction("install-blocked", evt.Path,
			fmt.Sprintf("type=%s reason=scanner-error scanner=%s (F-3187)",
				targetType, s.Name()))
		w.recordAdmission(ctx, "scan-error", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictBlocked,
			Reason:        reason,
			InstallAction: "block",
		}
		if !secureClient {
			res.RuntimeAction = "block"
		}
		return res
	}
	w.releaseScanFailureBlock(evt, targetType)

	// Phase 3: post-scan evaluation. Re-read the live config so a block or
	// allow added while the scan was running wins.
	decisionPolicy = w.admissionPolicySnapshot()
	admissionTrace.policyDigest, admissionTrace.policyGeneration = decisionPolicy.Digest, decisionPolicy.Generation
	input = w.admissionInputFor(decisionPolicy.Config, evt, targetType, connector)
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

	out = w.evaluateAdmissionSnapshot(ctx, input, decisionPolicy)
	w.applyPostScanEnforcement(ctx, out, evt, targetType, result, s.Name())
	scanID := w.logScanID(ctx, evt, result, out.Verdict)
	w.recordAdmission(ctx, out.Verdict, targetType)
	res = AdmissionResult{
		ScanID: scanID,
		Event:  evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason,
		MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
		InstallAction: out.InstallAction,
		FileAction:    out.FileAction,
		RuntimeAction: out.RuntimeAction,
		Unenforced:    out.Verdict == "rejected" && !w.takeActionFor(evt),
	}
	return res
}

// admissionInputFor builds the admission input from config: the compiled
// admission: for the asset type and the asset_policy block/allow lists that
// apply to the event's connector. Secure Client hosts keep their operator
// rows in the actions table, unchanged.
func (w *InstallWatcher) admissionInputFor(cfg *config.Config, evt InstallEvent, targetType, connector string) policy.AdmissionInput {
	block, allow := policy.AssetPolicyListsFor(cfg, w.withMCPDefinition(cfg, evt, config.AssetPolicyInput{
		TargetType: targetType, Name: evt.Name, DeclaredNames: declaredAssetNames(cfg, evt),
		Connector: connector, SourcePath: evt.Path,
	}))
	input := policy.AdmissionInput{
		TargetType: targetType,
		TargetName: evt.Name,
		Path:       evt.Path,
		BlockList:  block,
		AllowList:  allow,
		Admission:  policy.AdmissionFor(policy.CompileAdmission(cfg), targetType),
	}
	if cfg.SecureClientIntegration() {
		input.BlockList, input.AllowList = w.legacyListEntries("block"), w.legacyListEntries("allow")
	} else {
		input.VerifyFirstParty()
	}
	return input
}

// declaredAssetNames is the name a skill folder declares in its SKILL.md
// when it differs from the folder name. A denied rule matches it too, so a
// copy of a denied skill in a folder with another name is refused like the
// original (GAP-0581). A Secure Client host keeps the folder-name match of
// main (issue #1092).
func declaredAssetNames(cfg *config.Config, evt InstallEvent) []string {
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	if evt.Type == InstallPlugin {
		return declaredPluginNames(evt)
	}
	if evt.Type != InstallSkill {
		return nil
	}
	if name := assetfacts.DeclaredSkillName(evt.Path); name != "" && !config.SameAssetName(name, evt.Name) {
		return []string{name}
	}
	return nil
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
func (w *InstallWatcher) applyPostScanEnforcement(ctx context.Context, out *policy.AdmissionOutput, evt InstallEvent, targetType string, result *scanner.ScanResult, scannerName string) {
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
			if !w.secureClientActive() {
				// Name the findings that decided it, so the alert and skill
				// info show why the skill was blocked (GAP-0418).
				blockReason += decidingFindings(result)
			}
			if evt.readmitReason != "" {
				blockReason += "; " + evt.readmitReason
			}
			// An operator restore keeps the files only while the install
			// block it left in place remains. Decide that before this scan
			// adds its own block: after an unblock + restore, the block below
			// is a fresh decision and the files must be quarantined again,
			// not retained under a "quarantined" record (GAP-1971).
			retainRestored := w.preserveRestoredBlockedAsset(evt)

			installAction := coalesce(out.InstallAction, "block")
			runtimeAction := coalesce(out.RuntimeAction, "allow")
			fileAction := coalesce(out.FileAction, "none")
			scope := w.journalScope(w.eventConnector(evt))

			if installAction == "block" {
				_ = w.store.SetActionFieldForConnector(targetType, evt.Name, scope, "install", "block", blockReason)
			}
			_ = w.store.SetSourcePathForConnector(targetType, evt.Name, scope, evt.Path)

			enforcement := map[string]string{
				"source_path": evt.Path,
				"install":     installAction,
				"runtime":     runtimeAction,
				"file":        fileAction,
			}

			secureClient := w.secureClientActive()
			if fileAction == "quarantine" && !retainRestored && secureClient {
				_ = w.store.SetActionFieldForConnector(targetType, evt.Name, scope, "file", "quarantine", blockReason)
			}
			if runtimeAction == "block" {
				_ = w.store.SetActionFieldForConnector(targetType, evt.Name, scope, "runtime", "disable", blockReason)
			}

			_ = w.logger.LogActionWithEnforcement(string(audit.ActionWatcherBlock), evt.Name,
				fmt.Sprintf("type=%s reason=%s", targetType, blockReason), enforcement)

			// Only a file action of quarantine moves the files. The block
			// shorthand (install block, runtime disable, file none) leaves
			// them where they are.
			if fileAction == "quarantine" {
				err := w.enforceBlockWith(ctx, evt, retainRestored, "")
				if !retainRestored && !secureClient {
					// The journal says quarantined only once the files are
					// in quarantine storage; a failed move says so, plainly,
					// and the block and runtime disable stay (GAP-0394).
					switch {
					case err == nil:
						_ = w.store.SetActionFieldForConnector(targetType, evt.Name, scope, "file", "quarantine", blockReason)
					case errors.Is(err, errLinkRemoved):
						_ = w.store.SetActionFieldForConnector(targetType, evt.Name, scope, "install", "block", err.Error())
					default:
						_ = w.store.SetActionFieldForConnector(targetType, evt.Name, scope, "install", "block",
							quarantineFailedReason+err.Error())
					}
				}
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
	cfg := w.scanConfig()
	// Each scanner kind gets its own resolved LLMConfig so
	// ``scanners.{skill,mcp}.llm`` overrides layered on top of the
	// global ``llm:`` block take effect. Resolving per-event (rather
	// than caching once at watcher startup) means a config reload is
	// picked up automatically on the next install.
	switch evt.Type {
	case InstallSkill:
		ss := scanner.NewSkillScannerFromLLM(
			cfg.Scanners.SkillScanner,
			cfg.ResolveLLM("scanners.skill"),
			cfg.CiscoAIDefense,
		)
		ss.SecureClient = cfg.SecureClientIntegration()
		return w.withRulePackOverlay(ss, evt)
	case InstallMCP:
		ms := scanner.NewMCPScannerFromLLM(
			cfg.Scanners.MCPScanner,
			cfg.ResolveLLM("scanners.mcp"),
			cfg.CiscoAIDefense,
		)
		// The Windows scanner runtime applies the rule pack as the CLI does (GAP-0296).
		ms.RulePack = scanner.MCPRulePackFor(cfg, w.eventConnector(evt))
		if entry, err := w.lookupMCPServer(evt); err == nil {
			ms.ServerEntry = entry
			// A project-scoped command server is found only from its project
			// (GAP-0623).
			if entry.Project != "" && entry.URL == "" {
				if info, statErr := os.Stat(entry.Project); statErr == nil && info.IsDir() {
					ms.Project, ms.Connector = entry.Project, entry.Connector
				}
			}
		}
		return ms

	case InstallPlugin:
		plugin := scanner.NewPluginScanner(cfg.Scanners.PluginScanner)
		plugin.Connector = w.eventConnector(evt)
		return plugin
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
		return time.Duration(w.scanConfig().Scanners.SkillScanner.ScanTimeoutSeconds()) * time.Second
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

// decidingFindings names up to three findings at the scan's top severity,
// as ": RULE title; RULE title", or "" when there are none.
func decidingFindings(result *scanner.ScanResult) string {
	if result == nil {
		return ""
	}
	top := result.MaxSeverity()
	var named []string
	for _, f := range result.Findings {
		if f.Severity != top {
			continue
		}
		label := strings.TrimSpace(f.RuleID + " " + f.Title)
		if label == "" {
			continue
		}
		if len(named) == 3 {
			named = append(named, "...")
			break
		}
		named = append(named, label)
	}
	if len(named) == 0 {
		return ""
	}
	return ": " + strings.Join(named, "; ")
}

// journalScope is the connector the watcher's automatic enforcement rows
// belong to: the connector that holds the scanned copy, so blocking one
// connector's skill no longer disables another connector's skill (a
// vendor-bundled one included) that only shares its name (GAP-0393).
// OpenClaw, whose gateway enforces by name, and the Secure Client watcher
// keep the global row.
func (w *InstallWatcher) journalScope(connector string) string {
	connector = strings.ToLower(strings.TrimSpace(connector))
	if w.secureClientActive() || connector == "openclaw" {
		return ""
	}
	return connector
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
	w.enforceBlockWith(ctx, evt, true, "")
}

// readableAfterGrant looks, after a skill or plugin scan failed, for an
// entry of the folder the gateway may not read. It asks for read access
// (enforce.GrantAssetRead: the hook guardian on a managed Windows computer)
// and reports whether the folder is readable now, so the scan runs again;
// otherwise it says what stays unreadable (GAP-0825).
func (w *InstallWatcher) readableAfterGrant(evt InstallEvent) (bool, string) {
	if (evt.Type != InstallSkill && evt.Type != InstallPlugin) || w.admitsLinkedAsset(evt.Path) {
		return false, ""
	}
	denied := unreadableAssetEntry(addressablePath(evt.Path))
	if denied == "" {
		return false, ""
	}
	grantErr := enforce.GrantAssetRead(string(evt.Type), evt.Path)
	if grantErr == nil {
		if denied = unreadableAssetEntry(addressablePath(evt.Path)); denied == "" {
			fmt.Fprintf(os.Stderr, "[watch] %s %s: the gateway could not read it; read access granted, scanning again\n", evt.Type, evt.Path)
			return true, ""
		}
	}
	why := "the gateway service cannot read " + denied +
		" (a folder moved into a watched folder keeps the access list of where it came from)"
	if grantErr != nil && !errors.Is(grantErr, enforce.ErrNoAssetReadGranter) {
		why += "; read grant: " + grantErr.Error()
	}
	return false, why
}

// unreadableAssetEntry returns the first folder or file below root this
// process may not read, or "" (after at most 4096 entries).
func unreadableAssetEntry(root string) string {
	seen, denied := 0, ""
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				denied = path
				return filepath.SkipAll
			}
			return nil
		}
		if seen++; seen > 4096 {
			return filepath.SkipAll
		}
		if entry.Type().IsRegular() {
			file, openErr := os.Open(path)
			if errors.Is(openErr, fs.ErrPermission) {
				denied = path
				return filepath.SkipAll
			}
			if openErr == nil {
				_ = file.Close()
			}
		}
		return nil
	})
	return denied
}

// scanFailureReason leads the journal reason of an asset blocked and
// disabled because its scan failed; the next scan that succeeds releases
// that block and its verdict decides (releaseScanFailureBlock).
const scanFailureReason = "scanner failure (fail-closed): "

// recordScanFailureBlock journals the install block and runtime disable of
// an asset whose scan failed, for the connector that holds it.
func (w *InstallWatcher) recordScanFailureBlock(evt InstallEvent, targetType, reason string) {
	if w.store == nil {
		return
	}
	scope := w.journalScope(w.eventConnector(evt))
	_ = w.store.SetActionFieldForConnector(targetType, evt.Name, scope, "install", "block", reason)
	_ = w.store.SetActionFieldForConnector(targetType, evt.Name, scope, "runtime", "disable", reason)
	_ = w.store.SetSourcePathForConnector(targetType, evt.Name, scope, evt.Path)
}

// releaseScanFailureBlock clears the block and runtime disable a failed scan
// of this asset left, once a scan of it succeeds. The Secure Client profile
// journals no such block.
func (w *InstallWatcher) releaseScanFailureBlock(evt InstallEvent, targetType string) {
	if w.secureClientActive() || w.store == nil {
		return
	}
	scope := w.journalScope(w.eventConnector(evt))
	entry, err := w.store.GetActionForConnector(targetType, evt.Name, scope)
	if err != nil || entry == nil || !strings.HasPrefix(entry.Reason, scanFailureReason) ||
		(entry.SourcePath != "" && !sameWatcherPath(entry.SourcePath, evt.Path)) {
		return
	}
	for _, field := range []string{"runtime", "install"} {
		_ = w.store.ClearActionFieldForConnector(targetType, evt.Name, scope, field)
	}
}

// quarantineFailedReason and errLinkRemoved lead the journal reason of a
// blocked asset the watcher could not move into quarantine storage, and of a
// linked one it took out of the folder; skill list and skill info show them
// (cli/defenseclaw/commands/__init__.py compute_verdict reads the prefixes).
const quarantineFailedReason = "quarantine failed: "

var errLinkRemoved = errors.New("link removed")

// enforceBlockWith applies the block; honorRestore keeps the files of an
// operator-restored asset whose earlier install block still stands. reason,
// when set, is the quarantine record's reason (skill info shows it). The
// error is a failed quarantine (already reported) or errLinkRemoved.
func (w *InstallWatcher) enforceBlockWith(ctx context.Context, evt InstallEvent, honorRestore bool, reason string) error {
	switch evt.Type {
	case InstallMCP:
		// MCP servers have no filesystem artifact to quarantine. The sidecar's
		// handleMCPAdmission applies the block verdict to the connector's MCP
		// configuration from the admission result this watcher publishes.
	case InstallSkill, InstallPlugin:
		return w.quarantineAssetWith(ctx, evt, honorRestore, reason)
	}
	return nil
}

// pluginCategoryQuarantineDir is the quarantine tree of plugins in a Hermes
// category folder (cli/defenseclaw/enforce/plugin_enforcer.py mirrors it).
const pluginCategoryQuarantineDir = "plugin-categories"

func (w *InstallWatcher) quarantineAsset(ctx context.Context, evt InstallEvent) {
	_ = w.quarantineAssetWith(ctx, evt, true, "")
}

func (w *InstallWatcher) quarantineAssetWith(ctx context.Context, evt InstallEvent, honorRestore bool, reason string) error {
	if w == nil || w.cfg == nil || w.store == nil {
		err := fmt.Errorf("watcher: quarantine provenance store is unavailable")
		w.emitQuarantineFailure(ctx, evt, err)
		return err
	}
	if honorRestore && w.preserveRestoredBlockedAsset(evt) {
		_ = w.logger.LogAction(string(audit.ActionWatcherBlock), evt.Path,
			fmt.Sprintf("type=%s restored physical files retained while install block remains", evt.Type))
		return nil
	}
	if !w.secureClientActive() && enforce.IsLinkedAsset(evt.Path) {
		return w.removeLinkedAsset(ctx, evt)
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
		return err
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
	input := audit.CreateQuarantineRecordInput{
		TargetType: evt.Type.String(), TargetName: evt.Name,
		OriginalPath: plan.SourcePath, QuarantinePath: plan.QuarantinePath,
		ContentHash: plan.ContentHash, Reason: coalesce(reason, "watcher enforcement"),
		State: audit.QuarantineStatePending, OwnershipJSON: plan.OwnershipJSON,
		// The physical owner and global action scope are committed together so
		// either Go or Python restore clears the exact logical file decision.
		Connectors: []string{connector, ""},
	}
	record, err := w.store.CreateQuarantineRecord(ctx, input)
	if errors.Is(err, audit.ErrQuarantinePathTaken) {
		// Another asset of this name (in the folder of another user, or in
		// another folder) holds the default slot. The refusal left this one
		// active in its folder (GAP-0413); it gets a slot of its own.
		plan.QuarantinePath = plan.PerSourceQuarantinePath()
		input.QuarantinePath = plan.QuarantinePath
		record, err = w.store.CreateQuarantineRecord(ctx, input)
	}
	if err != nil {
		w.emitQuarantineFailure(ctx, evt, err)
		return err
	}
	if record.State == audit.QuarantineStateRestoring &&
		sameWatcherPath(record.RestorePath, plan.SourcePath) {
		matches, hashErr := enforce.AssetContentHashMatches(plan.SourcePath, record.ContentHash)
		if hashErr == nil && matches {
			_ = w.logger.LogAction(string(audit.ActionWatcherBlock), evt.Path,
				fmt.Sprintf("type=%s restore in progress; physical files retained", evt.Type))
			return nil
		}
	}
	if !w.secureClientActive() {
		enforce.RemoveStaleQuarantineStages(plan, record.ID)
	}
	if err := enforce.ExecuteAssetQuarantine(plan, record.ID); err != nil {
		// Roll back only an unmaterialized journal. A verified destination is
		// authoritative recovery data and must retain its pending provenance.
		if _, statErr := os.Lstat(plan.QuarantinePath); os.IsNotExist(statErr) {
			_ = w.store.DeleteQuarantineRecord(ctx, record.ID)
		}
		w.emitQuarantineFailure(ctx, evt, err)
		return err
	}
	if err := w.store.UpdateQuarantineRecordState(
		ctx, record.ID, audit.QuarantineStateActive, "",
	); err != nil {
		// The pending write-ahead record is intentionally retained and can be
		// finalized or restored after restart.
		fmt.Fprintf(os.Stderr, "[watch] quarantine provenance remains pending for %s: %v\n", evt.Path, err)
	}
	w.recordQuarantineAudit(ctx, audit.ActionQuarantine, evt, plan.QuarantinePath)
	w.forgetMovedAsset(evt)
	return nil
}

// forgetMovedAsset drops the rescan baseline of an asset that admission
// moved out of its folder, and keeps admission from writing one: on a
// managed computer the hook guardian removes the original later, so the
// baseline was written while the folder was still there, and a copy of the
// same skill put back at that path (by another user, or after the folder
// was recreated) was skipped as unchanged by the next rescan and stayed
// active (GAP-0551). The Secure Client profile keeps the earlier behaviour.
func (w *InstallWatcher) forgetMovedAsset(evt InstallEvent) {
	if w.secureClientActive() || w.store == nil {
		return
	}
	w.movedOut.Store(evt.Path, struct{}{})
	if err := w.store.DeleteTargetSnapshot(string(evt.Type), evt.Path); err != nil {
		fmt.Fprintf(os.Stderr, "[watch] forget baseline of %s: %v\n", evt.Path, err)
	}
}

// releaseAllowListed clears the runtime disable and the install block that
// an earlier verdict left in the journal for a skill or plugin that an allow
// rule now admits. An administrator who reviewed a blocked skill and added an
// asset_policy allow rule for it saw the copy admitted while the agent still
// refused it as runtime-disabled, and a managed computer has no enable
// command (GAP-0628). Quarantined copies are kept; the Secure Client profile
// keeps the earlier behaviour.
func (w *InstallWatcher) releaseAllowListed(evt InstallEvent, reason string) {
	if w.secureClientActive() || w.store == nil || (evt.Type != InstallSkill && evt.Type != InstallPlugin) ||
		w.allowedAuditReason(reason) != "allow-listed" {
		return
	}
	scope := w.journalScope(w.eventConnector(evt))
	entry, err := w.store.GetActionForConnector(string(evt.Type), evt.Name, scope)
	if err != nil || entry == nil {
		return
	}
	var cleared []string
	for field, value := range map[string]string{"runtime": entry.Actions.Runtime, "install": entry.Actions.Install} {
		if value == "" {
			continue
		}
		if err := w.store.ClearActionFieldForConnector(string(evt.Type), evt.Name, scope, field); err == nil {
			cleared = append(cleared, field+"="+value)
		}
	}
	if len(cleared) > 0 {
		sort.Strings(cleared)
		_ = w.logger.LogAction(string(audit.ActionEnable), evt.Path,
			fmt.Sprintf("type=%s released by an allow rule: cleared %s connector=%s", evt.Type, strings.Join(cleared, " "), scope))
	}
}

// allowRuleReleases reports a skill or plugin whose journal still blocks or
// disables it while an allow rule now admits it, so the rescan admits it
// again and releases it without a new copy (GAP-0628).
func (w *InstallWatcher) allowRuleReleases(ctx context.Context, evt InstallEvent) bool {
	if w.secureClientActive() || w.store == nil || (evt.Type != InstallSkill && evt.Type != InstallPlugin) {
		return false
	}
	connector := w.eventConnector(evt)
	entry, err := w.store.GetActionForConnector(string(evt.Type), evt.Name, w.journalScope(connector))
	if err != nil || entry == nil || (entry.Actions.Runtime == "" && entry.Actions.Install == "") {
		return false
	}
	cfg := w.liveConfig()
	out := w.evaluateAdmission(ctx, w.admissionInputFor(cfg, evt, string(evt.Type), connector))
	return out != nil && out.Verdict == "allowed" && w.allowedAuditReason(out.Reason) == "allow-listed"
}

// quarantinedCopyIsBack reports a skill or plugin at a path that holds an
// active quarantine of it: the original was moved out and a copy is back.
func (w *InstallWatcher) quarantinedCopyIsBack(ctx context.Context, evt InstallEvent) bool {
	if w.secureClientActive() || w.store == nil || (evt.Type != InstallSkill && evt.Type != InstallPlugin) {
		return false
	}
	records, err := w.store.ListQuarantineRecordsForConnector(ctx, evt.Type.String(), evt.Name, w.eventConnector(evt))
	if err != nil {
		return false
	}
	for _, record := range records {
		if record.State == audit.QuarantineStateActive && sameWatcherPath(record.OriginalPath, evt.Path) {
			return true
		}
	}
	return false
}

// movedByAdmission reports, once, that admission moved evt out.
func (w *InstallWatcher) movedByAdmission(evt InstallEvent) bool {
	_, moved := w.movedOut.LoadAndDelete(evt.Path)
	return moved
}

// admitsLinkedAsset reports a skill or plugin that is a symlink or Windows
// junction, which admission scans through its target and, when blocked,
// takes out of the folder. The Secure Client profile keeps the earlier
// behaviour.
func (w *InstallWatcher) admitsLinkedAsset(path string) bool {
	return !w.secureClientActive() && enforce.IsLinkedAsset(path)
}

// linkedAssetTarget is the folder a linked skill or plugin points to: the
// scanners do not follow a link at the root of what they scan, so a link to
// a skill with a critical finding was scanned as an empty folder and
// allowed (GAP-0394). An unresolvable link keeps its own path, whose scan
// then fails closed.
func linkedAssetTarget(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != filepath.Clean(path) {
		return resolved
	}
	target, err := os.Readlink(path) // a Windows junction
	if err != nil || strings.TrimSpace(target) == "" {
		return path
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return filepath.Clean(target)
}

// removeLinkedAsset takes a skill or plugin that is a symlink or Windows
// junction out of the watched folder: the link is removed and the folder it
// points to is never touched (GAP-0394). Before, quarantine refused the link
// and only gateway.log said so, while the skill read as quarantined.
func (w *InstallWatcher) removeLinkedAsset(ctx context.Context, evt InstallEvent) error {
	target, err := enforce.RemoveLinkedAsset(w.sourceRootsFor(evt.Type), evt.Type.String(), evt.Path)
	if err != nil {
		w.emitQuarantineFailure(ctx, evt, err)
		return err
	}
	if target == "" {
		target = "an unreadable target"
	}
	w.forgetMovedAsset(evt)
	removed := fmt.Errorf("%w: it pointed to %s; that folder was not changed", errLinkRemoved, target)
	_ = w.logger.LogEventCtx(ctx, audit.Event{
		Action:   string(audit.ActionWatcherBlock),
		Target:   evt.Path,
		Actor:    "defenseclaw",
		Details:  fmt.Sprintf("type=%s %v", evt.Type, removed),
		Severity: "HIGH",
	})
	fmt.Fprintf(os.Stderr, "[watch] quarantine %s: %v\n", evt.Path, removed)
	return removed
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
		// A block whose quarantine move failed, whose link the watcher
		// removed, or whose scan failed was never restored by an operator: a
		// copy that shows up again is quarantined (GAP-0394 keeps
		// file=quarantine off the journal until the move succeeds).
		if strings.HasPrefix(entry.Reason, quarantineFailedReason) || strings.HasPrefix(entry.Reason, errLinkRemoved.Error()) ||
			strings.HasPrefix(entry.Reason, scanFailureReason) {
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
			defer w.state.set(w.classifyEvent(child), AdmissionPending)
		}
		w.mu.Unlock()
	}
}

// claudeStagingGrace is how long the rescan leaves a Claude Code plugin
// staging folder alone; one that stays longer is scanned as a plugin.
const claudeStagingGrace = 15 * time.Minute

// inClaudePluginStaging reports a path below a Claude Code plugin staging
// folder (cache/temp_local_<id>), younger than grace when grace is set.
// Claude Code builds a plugin there and then moves it to
// <marketplace>/<plugin>/<version>: the watcher scanned the staging copy as
// a plugin, blocked it for its missing manifest and held its files while the
// move ran, so even a clean plugin failed to install with EPERM (GAP-0629).
// The final folder is admitted as before. The Secure Client profile keeps
// the earlier behaviour.
func (w *InstallWatcher) inClaudePluginStaging(path string, grace time.Duration) bool {
	if w.secureClientActive() {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
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
		first := strings.FieldsFunc(relative, func(r rune) bool { return r == '/' || r == '\\' })[0]
		if !strings.HasPrefix(strings.ToLower(first), "temp_") {
			return false
		}
		if grace <= 0 {
			return true
		}
		info, statErr := os.Lstat(filepath.Join(rootAbs, first))
		return statErr == nil && time.Since(info.ModTime()) < grace
	}
	return false
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

// settleAdmissionIssue records what the admission of evt could not finish
// (its scan failed, or its files could not be moved to quarantine), so the
// watcher admits it again and status reports it, and a rejection take_action
// left unenforced; a finished admission forgets the earlier problem
// (GAP-0825, GAP-0826, GAP-0774). The Secure Client profile records none.
func (w *InstallWatcher) settleAdmissionIssue(evt InstallEvent, res AdmissionResult) {
	noted, hasNote := w.admissionNotes.LoadAndDelete(evt.Path)
	if res.Interrupted || w.secureClientActive() {
		return
	}
	if _, err := os.Lstat(addressablePath(evt.Path)); err != nil && evt.Type != InstallMCP {
		w.state.clearIssue(evt.Path) // moved to quarantine or removed
		return
	}
	issue := AdmissionIssue{Type: string(evt.Type), Name: evt.Name, Path: evt.Path, Connector: w.eventConnector(evt)}
	if owner, ok := w.ownerOf(evt.Path); ok {
		issue.Account = owner.Name
	}
	switch {
	case strings.HasPrefix(res.Reason, scanFailureReason):
		issue.Kind, issue.Detail = AdmissionUnscanned, strings.TrimPrefix(res.Reason, scanFailureReason)
	case hasNote:
		note, _ := noted.(AdmissionIssue)
		issue.Kind, issue.Detail = note.Kind, note.Detail
	case res.Unenforced:
		// Status reports it until take_action is on again and the rescan
		// enforces it (GAP-0774).
		issue.Kind = AdmissionNotEnforced
		issue.Detail = fmt.Sprintf("%s findings while gateway.watcher.%s.take_action is false", res.MaxSeverity, evt.Type)
	default:
		w.state.clearIssue(evt.Path)
		return
	}
	w.state.setIssue(issue)
}

// emitQuarantineFailure reports an asset the verdict blocked but the watcher
// could not move: it stays in place, so besides the log line and the metric
// the audit log records an enforcement failure the administrator can find
// (GAP-0133).
func (w *InstallWatcher) emitQuarantineFailure(ctx context.Context, evt InstallEvent, err error) {
	// A removal the hook guardian deferred to the user's next sign-in is the
	// guardian's to finish; status reports it from the guardian's list.
	if w != nil && !w.secureClientActive() && !errors.Is(err, enforce.ErrQuarantineRemovalDeferred) {
		w.admissionNotes.Store(evt.Path, AdmissionIssue{Kind: AdmissionNotQuarantined, Detail: err.Error()})
	}
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
	details := fmt.Sprintf("dest=%s", destPath)
	if owner, ok := w.ownerOf(evt.Path); ok && owner.Name != "" {
		// The row says whose asset it was (GAP-0575).
		details += " user=" + owner.Name
	}
	event := audit.Event{
		Action:   string(action),
		Target:   evt.Path,
		Actor:    "defenseclaw",
		Details:  details,
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
	info, err := os.Stat(addressablePath(path))
	// A link whose target the gateway cannot read is still admitted: its
	// scan fails closed and the link is taken out (GAP-0394).
	if (err != nil && !w.admitsLinkedAsset(path)) || (err == nil && !info.IsDir()) {
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
		w.ownedScanCorrelation(watcherScanCorrelation(ctx, "", w.eventConnector(evt)), result),
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
