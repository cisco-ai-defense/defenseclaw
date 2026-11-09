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
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/skillrootsafe"
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
	// definitionHash is, for an MCP server, the hash of the definition the
	// caller snapshotted for this admission (mcpDefinitionHash). Admission
	// decides and enforces only while the server still has that definition.
	definitionHash string
	// remembered is, for an MCP server the agent config no longer lists, the
	// definition it had when it was last listed (mcpAdmissionDeparted), so
	// an admission rule pinned to its URL or launcher is judged on it.
	remembered *config.MCPServerEntry
}

// admittingSnapshot binds an MCP admission to the definition snap hashed, so
// the verdict, the block and the release it makes are for that definition and
// no other. Other types, and a nil snapshot, are returned unchanged.
func (evt InstallEvent) admittingSnapshot(snap *TargetSnapshot) InstallEvent {
	if evt.Type == InstallMCP && snap != nil {
		evt.definitionHash = snap.ContentHash
	}
	return evt
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
	// Interrupted is a scan the watcher's own stop cut off, or an MCP
	// admission whose server no longer has the definition it was started
	// for: nothing was decided or enforced, no baseline is kept, and the
	// next start or cycle admits the asset it finds.
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
	cfg            *config.Config
	skillDirs      []string
	pluginDirs     []string
	rootCoverageMu sync.RWMutex
	rootNotifyMu   sync.Mutex
	rootCoverage   map[string]RootCoverageIssue
	onRootCoverage func([]RootCoverageIssue)
	// rootWarnings are admitted roots watched closely (RootWarning); the
	// notify mutex orders the handler calls.
	rootWarnMu       sync.RWMutex
	rootWarnNotifyMu sync.Mutex
	rootWarnings     map[string]RootWarning
	onRootWarning    func([]RootWarning)
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
	// lastAllowLists tracks changes that can revoke admission of unchanged
	// skills and plugins (rescan goroutine only).
	lastAllowLists string
	// mcpUpgradeBaseline is the source digest of the 0.8.x config migration
	// whose MCP servers the startup rescan baselines instead of admitting;
	// empty when there is none or a cycle already did (rescan goroutine only).
	mcpUpgradeBaseline string
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
	// hermesVendorNoted holds the shipped Hermes plugins already reported as
	// vendor content in this process, so a rescan cycle reports each once.
	hermesVendorNoted sync.Map
	// hermesManifests reads shipped Hermes plugin manifests through the
	// plugin scanner (manifestLoader); a test may set it.
	hermesManifests    hermesManifestLoader
	hermesManifestOnce sync.Once
	// hermesManifestPolicy applies the outage policy to the scanner's answers.
	hermesManifestPolicy *hermesManifestPolicy
	// markedWatchRoots caches the root markers written by this process
	// (rescan goroutine only).
	markedWatchRoots map[string]bool
	store            *audit.Store
	logger           *audit.Logger
	opa              *policy.Engine
	webhooks         WebhookDispatcher
	debounce         time.Duration
	onAdmit          OnAdmission

	mu               sync.Mutex
	pending          map[string]time.Time // path → first-seen, for debounce
	quarantineMoveMu sync.Mutex

	// pluginWaiting holds plugin-root folders that had nothing to admit yet
	// (empty or category folders, GAP-2449) and skill folders without a
	// markdown file yet (GAP-0900); they are watched for what lands in them,
	// and addWatch adds such a watch. Both are used on the Run goroutine only.
	pluginWaiting map[string]struct{}
	addWatch      func(dir string)
	// addContentWatch watches a skill folder's files (GAP-1087); Run sets it.
	addContentWatch func(dir string)
	// Reader and watch-progress hooks let focused tests measure a large move-in.
	onReadEvent           func(fsnotify.Event)
	onNestedWatchProgress func(string)

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

	// rootRoute judges the link route of a root. Nil means
	// skillrootsafe.ResolveWithWarnings; tests set it before Run and never
	// change it afterwards.
	rootRoute func(string, func(string) (string, error)) (string, []string, error)

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
	// rootConsumers retains every connector that loads a watched root. The
	// event owner above stays singular, while root coverage applies to all
	// consumers of a shared skill or plugin folder.
	rootConsumers map[string][]string
	// assetOwners names the account of each enrolled home, longest home
	// first (SetAssetOwners).
	assetOwners []AssetOwner

	// mcpServers lists the MCP servers admission and the rescan see. Nil
	// reads the connector config in the gateway's own home.
	mcpServers func() ([]config.MCPServerEntry, error)
	// mcpAdmissionKnown is the last successfully listed definition identity
	// for each server. A later list error can still preserve a completed
	// failed-scan decision for that definition.
	mcpAdmissionMu     sync.RWMutex
	mcpAdmissionKnown  []mcpKnownDefinition
	mcpAdmissionListed bool
	// mcpAdmissionDeparted holds, by definition (mcpDepartedKey), the servers
	// an earlier listing had and a later one did not, or had under another
	// definition: an agent that dropped or edited the entry can keep the live
	// connection. An admission the policy gave them stays revocable through
	// it (GAP-0920). Bounded; a listing that has the definition again drops
	// it. Only servers admitted before any scan are held. Guarded by
	// mcpAdmissionMu.
	mcpAdmissionDeparted map[string]mcpKnownDefinition
	// mcpAdmissionLost notes, per connector and account, the departed servers
	// that did not fit (mcpLostScope). mcpAdmissionLostKeys counts the
	// definitions noted across scopes. Guarded by mcpAdmissionMu.
	mcpAdmissionLost     map[string]*mcpLostScope
	mcpAdmissionLostKeys int
	// A slower older list read must not replace a newer completed listing.
	mcpAdmissionReadSeq  atomic.Uint64
	mcpAdmissionKnownSeq uint64 // guarded by mcpAdmissionMu
	// mcpOutcomes keeps, per server key, the latest admission outcome this
	// process completed for a definition (its hash and whether it was a scan
	// failure), from the moment the verdict is decided until the baseline
	// that records it is written. The hook reads it with the stored baseline,
	// so a completed verdict is visible before (or without) the baseline
	// write: a failure is never read as pending, and an allow that replaces
	// a failure is not held back by the old failed baseline (GAP-0775,
	// GAP-0778). Guarded by mcpAdmissionMu.
	mcpOutcomes map[string]mcpAdmissionOutcome
	// admitNewMCP runs install admission for an MCP server that appears
	// after the first rescan cycle (set with SetMCPServerSource): a managed
	// computer has no `mcp set`, so a user adding a server to their agent is
	// its install.
	admitNewMCP bool

	// rescanNow asks the rescan loop for a cycle before its interval ends.
	rescanNow chan struct{}
	// warnedRescanNow asks for a rescan of the roots watched closely when
	// periodic rescan is off (GAP-0905); rescanNow has no receiver then.
	warnedRescanNow chan struct{}
	// runtimeNotReady says a scan of this rescan cycle found the managed
	// scanner runtime not ready; runtimeRetries counts the cycles in a row
	// that did (nextRescanDelay, GAP-0975).
	runtimeNotReady atomic.Bool
	runtimeRetries  int

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
	mcpClaims  map[string]time.Time
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
	// loops tracks the rescan, added-MCP and MCP discovery loops Run starts;
	// Run returns only after they ended, so the store a caller closes next
	// is not read by a cycle still running (p0-round GAP-1423).
	loops sync.WaitGroup
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

// RootCoverageIssue is a configured asset root whose admission scan is off.
// Health exposes counts, connector names and, when another account can write a
// folder of the link route, that folder (Ancestor); the gateway log names the
// root paths.
type RootCoverageIssue struct {
	Kind, Path, Connector, Reason string
	// Ancestor is the folder of the root's link route that another account
	// can write (skillrootsafe.WritableAncestorError), else empty.
	Ancestor   string
	Connectors []string
}

// RootConsumer names a connector that loads a watched skill or plugin root.
type RootConsumer struct {
	Kind, Path, Connector string
}

// SetRootCoverageHandler publishes changes to the gateway's watcher health.
// Call before Run starts.
func (w *InstallWatcher) SetRootCoverageHandler(handler func([]RootCoverageIssue)) {
	w.onRootCoverage = handler
}

// RootCoverageIssues returns a snapshot for runtime admission checks.
func (w *InstallWatcher) RootCoverageIssues() []RootCoverageIssue {
	w.rootCoverageMu.RLock()
	defer w.rootCoverageMu.RUnlock()
	issues := make([]RootCoverageIssue, 0, len(w.rootCoverage))
	for _, issue := range w.rootCoverage {
		issue.Connectors = append([]string(nil), issue.Connectors...)
		issues = append(issues, issue)
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Path < issues[j].Path })
	return issues
}

// RootWarning is a configured asset root that is admitted and scanned, but
// whose link route passes group-writable folders that only a private group made
// acceptable, on a host where pam_group is loaded and can add an account to that
// group at login (GAP-0905). The watcher scans the root again on every change
// under it. Folders are the folders to run chmod g-w on.
type RootWarning struct {
	Kind, Path string
	Connectors []string
	Folders    []string
}

// SetRootWarningHandler publishes changes of the root warnings to the
// gateway watcher health. Call before Run starts.
func (w *InstallWatcher) SetRootWarningHandler(handler func([]RootWarning)) {
	w.onRootWarning = handler
}

// RootWarnings returns a snapshot of the roots watched closely.
func (w *InstallWatcher) RootWarnings() []RootWarning {
	w.rootWarnMu.RLock()
	defer w.rootWarnMu.RUnlock()
	warnings := make([]RootWarning, 0, len(w.rootWarnings))
	for _, warning := range w.rootWarnings {
		warning.Connectors = append([]string(nil), warning.Connectors...)
		warning.Folders = append([]string(nil), warning.Folders...)
		warnings = append(warnings, warning)
	}
	sort.Slice(warnings, func(i, j int) bool { return warnings[i].Path < warnings[j].Path })
	return warnings
}

// rootWarned reports whether path is at or below a root watched closely: the
// event loop asks a rescan for every change there.
func (w *InstallWatcher) rootWarned(path string) bool {
	w.rootWarnMu.RLock()
	defer w.rootWarnMu.RUnlock()
	for _, warning := range w.rootWarnings {
		if watcherPathAtOrBelow(path, warning.Path) {
			return true
		}
	}
	return false
}

// refreshRootWarning judges the link route of an admitted root again.
func (w *InstallWatcher) refreshRootWarning(kind, path string) {
	route := w.rootRoute
	if route == nil {
		route = skillrootsafe.ResolveWithWarnings
	}
	_, folders, err := route(path, watcherEvalSymlinks)
	if err != nil {
		folders = nil
	}
	w.setRootWarning(kind, path, folders)
}

// setRootWarning records the folders of a root watched closely, or clears the
// record when there are none.
func (w *InstallWatcher) setRootWarning(kind, path string, folders []string) {
	w.rootWarnNotifyMu.Lock()
	defer w.rootWarnNotifyMu.Unlock()
	key := kind + "\x00" + filepath.Clean(path)
	w.rootWarnMu.Lock()
	previous, hadPrevious := w.rootWarnings[key]
	if len(folders) == 0 {
		delete(w.rootWarnings, key)
	} else {
		if w.rootWarnings == nil {
			w.rootWarnings = make(map[string]RootWarning)
		}
		connectors := w.rootConsumers[kind+"\x00"+w.rootCoveragePath(path)]
		if len(connectors) == 0 {
			if connector := w.connectorForPath(path); connector != "" {
				connectors = []string{connector}
			}
		}
		w.rootWarnings[key] = RootWarning{Kind: kind, Path: filepath.Clean(path),
			Connectors: append([]string(nil), connectors...), Folders: slices.Clone(folders)}
	}
	current, has := w.rootWarnings[key]
	w.rootWarnMu.Unlock()
	if hadPrevious == has && slices.Equal(previous.Folders, current.Folders) && slices.Equal(previous.Connectors, current.Connectors) {
		return
	}
	if has {
		fmt.Fprintf(os.Stderr, "[watch] warning: %s root %s is reached through group-writable folders (%s) and pam_group is loaded; it is admitted and every change under it is scanned again; run chmod g-w on the folders\n",
			kind, path, strings.Join(current.Folders, ", "))
	} else {
		fmt.Fprintf(os.Stderr, "[watch] %s root %s is no longer reached through group-writable folders\n", kind, path)
	}
	if w.onRootWarning != nil {
		w.onRootWarning(w.RootWarnings())
	}
}

func (w *InstallWatcher) setRootCoverage(kind, path string, cause error) {
	if w == nil || w.secureClientActive() {
		return
	}
	// An admitted root is judged for the warning on every call; a root that
	// is not admitted has none.
	if cause == nil {
		w.refreshRootWarning(kind, path)
	} else {
		w.setRootWarning(kind, path, nil)
	}
	w.rootNotifyMu.Lock()
	defer w.rootNotifyMu.Unlock()
	key := kind + "\x00" + filepath.Clean(path)
	w.rootCoverageMu.Lock()
	previous, hadPrevious := w.rootCoverage[key]
	if cause == nil {
		if hadPrevious {
			delete(w.rootCoverage, key)
		}
	} else {
		if w.rootCoverage == nil {
			w.rootCoverage = make(map[string]RootCoverageIssue)
		}
		connectors := w.rootConsumers[kind+"\x00"+w.rootCoveragePath(path)]
		if len(connectors) == 0 {
			connector := w.connectorForPath(path)
			if connector == "" && w.cfg != nil {
				connector = w.cfg.Guardrail.Connector
			}
			if connector != "" {
				connectors = []string{connector}
			}
		}
		connector := ""
		if len(connectors) > 0 {
			connector = connectors[0]
		}
		ancestor := ""
		var writable *skillrootsafe.WritableAncestorError
		if errors.As(cause, &writable) {
			ancestor = writable.Ancestor
		}
		w.rootCoverage[key] = RootCoverageIssue{Kind: kind, Path: path, Connector: connector, Connectors: append([]string(nil), connectors...), Reason: cause.Error(), Ancestor: ancestor}
	}
	current := w.rootCoverage[key]
	changed := hadPrevious != (cause != nil) || (cause != nil &&
		(previous.Kind != current.Kind || previous.Path != current.Path || previous.Connector != current.Connector ||
			previous.Reason != current.Reason || !slices.Equal(previous.Connectors, current.Connectors)))
	w.rootCoverageMu.Unlock()
	if !changed {
		return
	}
	if cause != nil {
		fmt.Fprintf(os.Stderr, "[watch] warning: %s admission scanning is off for connectors %s root %s: %v\n", kind, strings.Join(current.Connectors, ", "), path, cause)
	} else {
		fmt.Fprintf(os.Stderr, "[watch] %s admission scanning resumed for root %s\n", kind, path)
	}
	if w.onRootCoverage != nil {
		w.onRootCoverage(w.RootCoverageIssues())
	}
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
	return AssetOwnerOf(w.assetOwners, path)
}

// AssetOwnerOf is the account among owners whose home holds path; the
// deepest home wins. The gateway's scan API uses it too, so a scan an
// administrator runs on an enrolled user's asset names that user, as the
// watcher's rows do (GAP-0575).
func AssetOwnerOf(owners []AssetOwner, path string) (AssetOwner, bool) {
	if strings.TrimSpace(path) == "" {
		return AssetOwner{}, false
	}
	var found AssetOwner
	ok := false
	for _, owner := range owners {
		if home := strings.TrimSpace(owner.Home); home != "" && watcherPathAtOrBelow(path, home) && (!ok || len(home) > len(found.Home)) {
			found, ok = owner, true
		}
	}
	return found, ok
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
	addressable := addressableStandalonePath
	if cfg.SecureClientIntegration() {
		addressable = addressablePath
	}
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

		warnedRescanNow: make(chan struct{}, 1),

		admitMCPNow: make(chan struct{}, 1),

		state:        newAdmissionState(cfg.DataDir, addressable),
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

// SetRootConsumers records all connectors that load each watched root. Call
// before Run, alongside SetRootConnectors for the event owner.
func (w *InstallWatcher) SetRootConsumers(consumers []RootConsumer) {
	w.rootConsumers = make(map[string][]string)
	for _, consumer := range consumers {
		connector := strings.ToLower(strings.TrimSpace(consumer.Connector))
		if connector == "" || strings.TrimSpace(consumer.Path) == "" {
			continue
		}
		key := consumer.Kind + "\x00" + w.rootCoveragePath(consumer.Path)
		if !slices.Contains(w.rootConsumers[key], connector) {
			w.rootConsumers[key] = append(w.rootConsumers[key], connector)
		}
	}
}

func (w *InstallWatcher) rootCoveragePath(path string) string {
	cleaned, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		cleaned = filepath.Clean(path)
	}
	if runtime.GOOS == "windows" {
		cleaned = strings.ToLower(cleaned)
	}
	return cleaned
}

// SetMCPServerSource replaces where admission and the rescan read the MCP
// servers (a managed gateway reads every enrolled user's). Call it before Run.
func (w *InstallWatcher) SetMCPServerSource(source func() ([]config.MCPServerEntry, error)) {
	w.mcpServers = source
	w.admitNewMCP = source != nil
	w.mcpAdmissionMu.RLock()
	prev := w.mcpAdmissionKnown
	w.mcpAdmissionMu.RUnlock()
	settled := w.settledDepartingMCP(prev, nil)
	w.mcpAdmissionMu.Lock()
	w.rememberDepartedMCP(w.mcpAdmissionKnown, nil, settled)
	w.mcpAdmissionKnown = nil
	w.mcpAdmissionListed = false
	w.mcpAdmissionKnownSeq = w.mcpAdmissionReadSeq.Add(1)
	w.mcpAdmissionMu.Unlock()
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
	baseline, err := w.mcpSnapshotForEvent(evt)
	if err == nil {
		w.readmitChangedMCPServer(ctx, evt, baseline)
		return // admitted or baselined already
	}
	if !errors.Is(err, sql.ErrNoRows) {
		fmt.Fprintf(os.Stderr, "[watch] mcp %s was added; its baseline could not be read, retrying: %v\n", evt.Name, err)
		w.queueAddedMCP(evt.Name)
		return
	}
	snap, err := w.snapshotForEvent(evt)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Said, not skipped in silence: a server that never reached
			// admission left no row at all (GAP-0219).
			fmt.Fprintf(os.Stderr, "[watch] mcp %s was added but is no longer listed; admission waits for the next listing\n", evt.Name)
		} else {
			fmt.Fprintf(os.Stderr, "[watch] mcp %s was added; reading its definition failed: %v\n", evt.Name, err)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "[watch] mcp %s was added; running install admission\n", evt.Name)
	res := w.runAdmission(ctx, evt.admittingSnapshot(snap))
	w.noteMCPAdmissionOutcome(evt, snap, res)
	w.notifyAdmission(res)
	if !res.Interrupted {
		w.persistSnapshot(evt, snap, res.ScanID, w.admissionFingerprint(res, w.cachedFingerprint(evt, nil)))
	}
}

// readmitChangedMCPServer admits again, now, a queued MCP server whose
// definition changed since its baseline (command, arguments, folder or
// environment under the same name). Its verdict was for the old definition,
// and the hook refuses its calls until admission has run on the new one
// (MCPAdmissionPending); the rescan cycle would admit it only at its next
// pass (GAP-0216). An unchanged server is left as it is. Secure Client keeps
// main (issue #1092).
func (w *InstallWatcher) readmitChangedMCPServer(ctx context.Context, evt InstallEvent, baseline *audit.SnapshotRow) {
	if baseline == nil || w.secureClientActive() {
		return
	}
	snap, err := w.snapshotForEvent(evt)
	if err != nil || (snap.ContentHash == baseline.ContentHash && !w.mcpScanRetryDue(evt.Path, baseline) &&
		!w.mcpBaselineLapsed(evt, baseline)) {
		return
	}
	w.readmitChanged(ctx, evt, baseline, snap, compareSnapshots(baseline, snap), w.cachedFingerprint(evt, nil), "watch")
}

// mcpScanRetryDue reports an unchanged MCP server whose last admission scan
// failed (mcpScanFailedMark) and whose retry is due: 2 minutes after the
// first failure, doubling to 30 (admissionState). A launcher refusal is never
// due: it is final for its definition (rel-1-0-6:GAP-0258).
func (w *InstallWatcher) mcpScanRetryDue(path string, baseline *audit.SnapshotRow) bool {
	return baseline != nil && !w.secureClientActive() && strings.HasSuffix(baseline.ScannerFingerprint, mcpScanFailedMark) &&
		w.state.mcpRetryDue(path)
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
	if _, claimed := w.mcpClaims[path]; claimed {
		return false
	}
	if w.mcpClaims == nil {
		w.mcpClaims = map[string]time.Time{}
	}
	w.mcpClaims[path] = time.Now()
	return true
}

func (w *InstallWatcher) mcpRetryAfter(path string) time.Duration {
	w.mcpClaimMu.Lock()
	started, claimed := w.mcpClaims[path]
	w.mcpClaimMu.Unlock()
	if !claimed {
		return defaultScanTimeout
	}
	return max(time.Second, defaultScanTimeout-time.Since(started))
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

// DiscoverAddedMCPServers admits now every MCP server without a baseline,
// and admits again every server whose definition changed since its
// baseline. A managed gateway calls it when its enrolled users servers
// change.
func (w *InstallWatcher) DiscoverAddedMCPServers() {
	if w == nil || !w.admitNewMCP {
		return
	}
	w.discoverAddedMCPServers()
}

// discoverAddedMCPServers queues for admission the MCP servers that have no
// baseline yet, and the servers whose definition changed since their
// baseline: a verdict is for one definition, and only the rescan cycle used
// to see a change, minutes later, while the hook kept allowing the changed
// server's calls on the old verdict (GAP-0216). It starts once the first
// rescan cycle listed the existing servers, which that cycle baselines; it
// does not wait for the cycle to end, which after an upgrade rescans every
// skill for many minutes (GAP-0254).
func (w *InstallWatcher) discoverAddedMCPServers() {
	firstCycle := !w.firstCycleDone.Load()
	if (firstCycle && !w.mcpStartupListed.Load()) || w.store == nil {
		return
	}
	servers, err := w.readMCPServers()
	if err != nil {
		return
	}
	if !firstCycle {
		// The issue of a server no longer configured is forgotten: only
		// admission cleared one, so a removed project left status and
		// verify warning about it (GAP-0134).
		listed := make(map[string]bool, len(servers))
		for _, server := range servers {
			listed[MCPEventPath(server)] = true
		}
		w.state.forgetMCPIssuesNotListed(listed)
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
		baseline, err := mcpSnapshotForServer(w.store, server)
		if err != nil {
			// A read error other than no rows is retried by admission,
			// which says so.
			added = append(added, server.Name)
			continue
		}
		if !w.secureClientActive() && !mcpBaselineMatches(baseline, server) {
			// Admitted again at once (readmitChangedMCPServer).
			added = append(added, server.Name)
		} else if w.mcpScanRetryDue(path, baseline) {
			// Its scan failed: tried again with backoff, not every poll
			// (rel-1-0-6:GAP-0258).
			added = append(added, server.Name)
		}
	}
	w.AdmitAddedMCPServers(added)
}

// readMCPServers is the MCP server list admission and the rescan use.
func (w *InstallWatcher) readMCPServers() ([]config.MCPServerEntry, error) {
	if !w.admitNewMCP {
		if w.mcpServers != nil {
			return w.mcpServers()
		}
		return w.cfg.ReadMCPServers()
	}
	readSeq := w.mcpAdmissionReadSeq.Add(1)
	var servers []config.MCPServerEntry
	var err error
	if w.mcpServers != nil {
		servers, err = w.mcpServers()
	} else {
		servers, err = w.cfg.ReadMCPServers()
	}
	if err == nil {
		known := make([]mcpKnownDefinition, 0, len(servers))
		for _, server := range servers {
			hash, hashErr := mcpDefinitionHash(server)
			if hashErr != nil {
				continue
			}
			known = append(known, mcpKnownDefinition{
				server: config.MCPServerEntry{Name: server.Name, Connector: server.Connector,
					Home: server.Home, Project: server.Project, Bundled: server.Bundled,
					URL: server.URL, Command: server.Command, Args: append([]string(nil), server.Args...),
					Transport: server.Transport},
				hash:  hash,
				path:  MCPEventPath(server),
				issue: mcpScanIssue(server),
			})
		}
		w.mcpAdmissionMu.RLock()
		prev := w.mcpAdmissionKnown
		w.mcpAdmissionMu.RUnlock()
		settled := w.settledDepartingMCP(prev, known)
		w.mcpAdmissionMu.Lock()
		if readSeq > w.mcpAdmissionKnownSeq {
			w.rememberDepartedMCP(w.mcpAdmissionKnown, known, settled)
			w.mcpAdmissionKnown = known
			w.mcpAdmissionListed = true
			w.mcpAdmissionKnownSeq = readSeq
		}
		w.mcpAdmissionMu.Unlock()
	}
	return servers, err
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

// addressableAssetPath preserves standalone Windows trailing names while the
// Secure Client profile keeps its original watcher path handling.
func (w *InstallWatcher) addressableAssetPath(path string) string {
	if w.secureClientActive() {
		return addressablePath(path)
	}
	return addressableStandalonePath(path)
}

func (w *InstallWatcher) assetEventName(path string) string {
	if w.secureClientActive() {
		return filepath.Base(path)
	}
	return physicalAssetName(path)
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
	// Moved-in recursive trees are registered by one worker. Its watch keys
	// are separate from Run's keys so the event reader never shares a map with
	// the walk. The small lock also coordinates a directory removal with Add.
	nestedWatches := make(map[string]struct{})
	watchTasks := make(map[string]struct{})
	watchWake := make(chan struct{}, 1)
	var nestedMu sync.Mutex
	watchAsync := false
	w.addWatch = func(dir string) {
		if w.secureClientActive() {
			addDirWatchesLegacy(fsw, dir, 0, watchedDirs)
		} else {
			for _, root := range w.pluginDirs {
				if watcherPathAtOrBelow(dir, root) && !sameWatcherPath(dir, root) &&
					unlinkedSkillTreePath(root, dir) != nil {
					return
				}
			}
			addDirWatches(fsw, dir, 0, watchedDirs)
		}
	}
	w.addContentWatch = func(dir string) {
		if !w.secureClientActive() {
			for _, root := range w.skillDirs {
				if watcherPathAtOrBelow(dir, root) {
					if err := unlinkedSkillTreePath(root, dir); err != nil {
						w.setRootCoverage("skill", root, err)
						return
					}
				}
			}
		}
		if root, _, recursive := w.recursiveSkillRoot(dir); recursive {
			if watchAsync {
				nestedMu.Lock()
				watchTasks[filepath.Clean(dir)] = struct{}{}
				nestedMu.Unlock()
				select {
				case watchWake <- struct{}{}:
				default:
				}
				return
			}
			addNestedSkillWatches(ctx, fsw, root, dir, watchedDirs, nil, nil)
			return
		}
		addSkillContentWatches(fsw, dir, watchedDirs)
	}
	var deferredDirs [][2]string // {dir, kind} not created because an agent installer owns them
	// missingDirs are configured roots the watcher could not create (an
	// admin-only parent made later, GAP-2628). Each tick checks them again;
	// once one exists it is watched and what it already holds is admitted.
	var missingDirs [][2]string
	watchKey := func(dir string) (string, string) {
		absolute, absErr := filepath.Abs(dir)
		if absErr != nil {
			absolute = filepath.Clean(dir)
		}
		return strings.ToLower(filepath.Clean(absolute)), absolute
	}
	// roots remembers the folder each skill and plugin root was when it was
	// watched. A rename or removal of a root drops its watch and nothing
	// watched the folder made again at that path, so a skill put there got
	// only a rescan baseline, never an install verdict (GAP-1315). Secure
	// Client keeps the behaviour of main.
	roots := make(map[string]watchedRoot)
	rememberRoot := func(key, dir, absolute, kind string) {
		if w.secureClientActive() {
			return
		}
		if info, statErr := pathidentity.StatPinned(dir); statErr == nil {
			roots[key] = watchedRoot{dir: dir, absolute: absolute, kind: kind, info: info, checked: time.Now()}
		}
	}
	// rewatchRoot watches a root again once the folder at its path is not
	// the watched one, and queues what it holds for install admission.
	rewatchRoot := func(key string, root watchedRoot) {
		info, statErr := os.Stat(root.dir)
		if statErr != nil || !info.IsDir() {
			if statErr == nil {
				statErr = fmt.Errorf("watched root is not a directory: %s", root.dir)
			}
			root.failed, root.checked = true, time.Now()
			roots[key] = root
			w.setRootCoverage(root.kind, root.dir, statErr)
			return
		}
		_, watching := watchedDirs[key]
		same := os.SameFile(info, root.info)
		if same && watching && !root.failed && time.Since(root.checked) < time.Second {
			return
		}
		if !w.secureClientActive() {
			if err := unlinkedSkillTreePath(root.dir, root.dir); err != nil {
				nestedMu.Lock()
				forgetDirWatches(fsw, root.absolute, watchedDirs)
				forgetNestedWatchKeys(root.absolute, nestedWatches)
				nestedMu.Unlock()
				root.info, root.failed, root.checked = info, true, time.Now()
				roots[key] = root
				w.setRootCoverage(root.kind, root.dir, err)
				return
			}
		}
		root.checked = time.Now()
		if same && watching && !root.failed {
			roots[key] = root
			w.setRootCoverage(root.kind, root.dir, nil)
			return
		}
		nestedMu.Lock()
		forgetDirWatches(fsw, root.absolute, watchedDirs)
		forgetNestedWatchKeys(root.absolute, nestedWatches)
		nestedMu.Unlock()
		root.info, root.failed = info, false
		if addErr := fsw.Add(root.dir); addErr != nil {
			root.failed = true
			roots[key] = root
			w.setRootCoverage(root.kind, root.dir, addErr)
			return
		}
		w.setRootCoverage(root.kind, root.dir, nil)
		roots[key] = root
		watchedDirs[key] = struct{}{}
		fmt.Printf("[watch] %s dir %s was replaced; watching it again and admitting what it holds\n", root.kind, root.dir)
		w.admitReplacedRoot(ctx, fsw, root.dir, root.kind, watchedDirs)
	}
	watchOnce := func(dir, kind string) bool {
		key, absolute := watchKey(dir)
		if _, exists := watchedDirs[key]; exists {
			return true
		}
		if createsAgentOwnedDir(dir) {
			// Watched once the agent's own installer creates it (GAP-2354).
			deferredDirs = append(deferredDirs, [2]string{dir, kind})
			fmt.Printf("[watch] %s dir %s does not exist yet; watching it once the agent creates it\n", kind, dir)
			return false
		}
		if isAbsentVendorSystemDir(dir) {
			// Never created by the watcher: the agent treats the folder's
			// presence as administrator policy. Watched once it exists.
			deferredDirs = append(deferredDirs, [2]string{dir, kind})
			fmt.Printf("[watch] %s dir %s does not exist; watching it once an administrator creates it\n", kind, dir)
			return false
		}
		watchRoot := ensureAndWatchLegacy
		if !w.secureClientActive() {
			watchRoot = ensureAndWatch
		}
		created, err := watchRoot(fsw, dir)
		if len(created) > 0 {
			// Uninstall removes these again while they are empty (and the
			// OpenCode teardown removes its own).
			if recordErr := gatewayconnector.RecordWatcherCreatedDirs(w.cfg.DataDir, created); recordErr != nil {
				fmt.Fprintf(os.Stderr, "[watch] record created dirs: %v\n", recordErr)
			}
		}
		if err != nil {
			w.setRootCoverage(kind, dir, err)
			if errors.Is(err, errWatchDirNotCreated) {
				missingDirs = append(missingDirs, [2]string{dir, kind})
				return false
			}
			if !w.secureClientActive() {
				missingDirs = append(missingDirs, [2]string{dir, kind})
				return false
			}
			return false
		}
		w.setRootCoverage(kind, dir, nil)
		watchedDirs[key] = struct{}{}
		rememberRoot(key, dir, absolute, kind)
		watched++
		fmt.Printf("[watch] monitoring %s dir: %s\n", kind, dir)
		return true
	}
	for _, dir := range w.skillDirs {
		if watchOnce(dir, "skill") {
			w.watchIncompleteSkillFolders(dir)
			w.watchSkillContents(dir)
			// Claude Code syncs account skills two levels down
			// (skills/synced/<account>/<skill>); watch those folders too so
			// a newly synced skill is scanned on arrival (GAP-1409).
			synced := filepath.Join(dir, "synced")
			if depth, ok := w.claudeSyncedDepth(synced); ok && depth == 0 &&
				(w.secureClientActive() || unlinkedSkillTreePath(dir, synced) == nil) {
				if w.secureClientActive() {
					addDirWatchesLegacy(fsw, synced, 1, watchedDirs)
				} else {
					addDirWatches(fsw, synced, 1, watchedDirs)
				}
			}
		}
	}
	for _, dir := range w.pluginDirs {
		if !watchOnce(dir, "plugin") {
			continue
		}
		w.watchExistingPluginFolders(dir)
		if w.cacheLayoutPlugins(dir) &&
			strings.EqualFold(filepath.Base(filepath.Clean(dir)), "cache") {
			if w.secureClientActive() {
				addDirWatchesLegacy(fsw, dir, 2, watchedDirs)
			} else {
				addClaudeCacheWatches(fsw, dir, watchedDirs)
			}
		}
	}

	if watched == 0 && len(missingDirs) == 0 && !w.admitNewMCP {
		return fmt.Errorf("watcher: no directories to watch — check claw.mode and claw.home_dir")
	}

	_ = w.logger.LogAction(string(audit.ActionWatchStart), "", fmt.Sprintf("dirs=%d debounce=%s", watched, w.debounce))

	// The background loops stop with Run, whichever way it returns, and Run
	// waits for them: a rescan cycle reading baselines after Run returned
	// hit a closed store ("sql: database is closed") and ran beside the
	// cycle of the watcher that replaced this one (p0-round GAP-1423).
	loopCtx, stopLoops := context.WithCancel(ctx)
	defer func() {
		stopLoops()
		w.loops.Wait()
	}()
	startLoop := func(loop func(context.Context)) {
		w.loops.Add(1)
		go func() {
			defer w.loops.Done()
			loop(loopCtx)
		}()
	}
	watchAsync = !w.secureClientActive()
	if watchAsync {
		startLoop(func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					return
				case <-watchWake:
				}
				for {
					nestedMu.Lock()
					var subtree string
					for path := range watchTasks {
						subtree = path
						delete(watchTasks, path)
						break
					}
					nestedMu.Unlock()
					if subtree == "" {
						break
					}
					root, _, recursive := w.recursiveSkillRoot(subtree)
					if !recursive {
						continue
					}
					addNestedSkillWatches(ctx, fsw, root, subtree, nestedWatches, &nestedMu, func() {
						if w.onNestedWatchProgress != nil {
							w.onNestedWatchProgress(subtree)
						}
					})
				}
			}
		})
	}
	if w.cfg.Watch.RescanEnabled {
		startLoop(w.rescanLoop)
	} else {
		startLoop(w.warnedRescanLoop)
	}
	if w.admitNewMCP {
		startLoop(w.addedMCPLoop)
	}
	if w.pollMCP {
		if !w.cfg.Watch.RescanEnabled {
			w.firstCycleDone.Store(true)
		}
		startLoop(w.mcpDiscoveryLoop)
	}

	ticker := time.NewTicker(w.debounce)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// In-flight admissions see the stop and end without a verdict
			// (GAP-0335); wait for them and the loops before the store goes
			// away.
			stopLoops()
			w.loops.Wait()
			w.admissions.Wait()
			w.state.reset()
			_ = w.logger.LogAction(string(audit.ActionWatchStop), "", "context cancelled")
			return ctx.Err()

		case event, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if w.onReadEvent != nil {
				w.onReadEvent(event)
			}
			if w.rootWarned(event.Name) {
				// A root reached through group-writable folders of a private
				// group while pam_group is loaded: scan the root again for
				// every change under it (GAP-0905).
				w.requestWarnedRescan()
			}
			if event.Op&(fsnotify.Rename|fsnotify.Remove) != 0 {
				nestedMu.Lock()
				key := strings.ToLower(filepath.Clean(event.Name))
				_, rootWatched := watchedDirs[key]
				forgetDirWatches(fsw, event.Name, watchedDirs)
				if _, watched := nestedWatches[key]; watched {
					forgetDirWatches(fsw, event.Name, nestedWatches)
				} else if rootWatched {
					forgetNestedWatchKeys(event.Name, nestedWatches)
				}
				nestedMu.Unlock()
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename) != 0 && len(roots) > 0 {
				if key, _ := watchKey(event.Name); roots[key].dir != "" {
					rewatchRoot(key, roots[key])
				}
			}
			if event.Op&fsnotify.Create != 0 {
				if root, _, recursive := w.recursiveSkillRoot(event.Name); recursive &&
					!sameWatcherPath(event.Name, root) {
					if info, err := os.Lstat(event.Name); err == nil && info.IsDir() {
						w.addContentWatch(event.Name)
						if !w.inSkillInstallStaging(root, event.Name, 0) && !isBundledSkillWatchPath(event.Name) {
							w.recordWatcherEvent(ctx, "create", string(InstallSkill), "")
							w.queuePending(event.Name)
						}
						continue
					}
				}
			}
			if skill, inside := w.changedSkillFolder(event.Name); inside {
				w.skillFolderEvent(ctx, event, skill)
				continue
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if w.cacheLayoutPlugins(event.Name) {
				if depth, inside := w.claudeCacheDepth(event.Name); inside {
					if w.inClaudePluginStaging(event.Name, 0) {
						continue
					}
					copyRoot, copied := w.cachePluginCopyRoot(event.Name)
					if info, statErr := os.Lstat(event.Name); statErr == nil &&
						info.IsDir() && depth < 3 {
						if w.secureClientActive() {
							addDirWatchesLegacy(fsw, event.Name, 2, watchedDirs)
						} else {
							addClaudeCacheWatches(fsw, event.Name, watchedDirs)
						}
						if !copied {
							w.queueExistingClaudePlugins(ctx, event.Name, depth)
						}
					}
					if copied {
						w.recordWatcherEvent(ctx, "create", string(InstallPlugin), "")
						w.queuePending(copyRoot)
						continue
					}
					if depth != 3 {
						continue
					}
				}
			}
			if depth, inside := w.claudeSyncedDepth(event.Name); inside {
				if !w.secureClientActive() {
					valid := true
					for _, root := range w.skillDirs {
						if !watcherPathAtOrBelow(event.Name, root) {
							continue
						}
						check := event.Name
						if depth == 2 {
							check = filepath.Dir(check)
						}
						if err := unlinkedSkillTreePath(root, check); err != nil {
							fmt.Fprintf(os.Stderr, "[watch] synced skill directory %s: %v\n", event.Name, err)
							valid = false
							break
						}
					}
					if !valid {
						continue
					}
				}
				if info, statErr := os.Stat(event.Name); statErr != nil || !info.IsDir() {
					continue
				}
				switch depth {
				case 0:
					// The synced folder itself: watch it and its account
					// folders; the event below expands it into its skills.
					if w.secureClientActive() {
						addDirWatchesLegacy(fsw, event.Name, 1, watchedDirs)
					} else {
						addDirWatches(fsw, event.Name, 1, watchedDirs)
					}
				case 1:
					// A new account folder: watch it and queue the skills
					// already inside (they can land before the watch).
					if w.secureClientActive() {
						addDirWatchesLegacy(fsw, event.Name, 0, watchedDirs)
					} else {
						addDirWatches(fsw, event.Name, 0, watchedDirs)
					}
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
			if w.addContentWatch != nil && w.inSkillRoot(queued) {
				w.addContentWatch(queued)
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
			for key, root := range roots {
				rewatchRoot(key, root)
			}
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
			if len(missingDirs) > 0 {
				waiting := missingDirs
				missingDirs = nil
				for _, entry := range waiting {
					if info, statErr := os.Stat(entry[0]); statErr != nil || !info.IsDir() {
						missingDirs = append(missingDirs, entry)
						continue
					}
					if !w.secureClientActive() {
						if err := unlinkedSkillTreePath(entry[0], entry[0]); err != nil {
							w.setRootCoverage(entry[1], entry[0], err)
							missingDirs = append(missingDirs, entry)
							continue
						}
					}
					if watchOnce(entry[0], entry[1]) {
						fmt.Printf("[watch] %s dir %s exists now; admitting what it holds\n", entry[1], entry[0])
						w.admitReplacedRoot(ctx, fsw, entry[0], entry[1], watchedDirs)
					}
				}
			}
			w.queueDueIssues()
			w.processPending(ctx)
		}
	}
}

// forgetNestedWatchKeys clears the worker's records after Run removed all
// watches under a replaced root from fsnotify itself.
func forgetNestedWatchKeys(path string, watched map[string]struct{}) {
	key := strings.ToLower(filepath.Clean(path))
	for dir := range watched {
		if dir == key || strings.HasPrefix(dir, key+string(filepath.Separator)) {
			delete(watched, dir)
		}
	}
}

// queueDueIssues admits again what a failed scan or quarantine left in
// place. An issue an earlier watcher recorded under a folder this one does
// not watch (a connector that was removed or is no longer set up, a folder
// taken out of gateway.watcher) stays recorded but is not admitted: its
// quarantine can only fail as outside the watched folders, and it raised a
// HIGH alert on every retry (GAP-0574). Its install block and runtime
// disable stay in the journal; a watcher that watches the folder again
// retries it.
func (w *InstallWatcher) queueDueIssues() {
	for _, issue := range w.state.dueIssues(AdmissionUnscanned, AdmissionNotQuarantined) {
		roots := w.sourceRootsFor(InstallType(issue.Type))
		if !slices.ContainsFunc(roots, func(root string) bool { return watcherPathAtOrBelow(issue.Path, root) }) {
			continue
		}
		if issue.Kind == AdmissionNotQuarantined && w.blockedPluginDecisionUnchanged(issue) {
			continue
		}
		w.queuePending(issue.Path)
	}
}

// An unchanged, disabled plugin already has a final admission decision. A
// failed physical move remains visible, while a changed copy is admitted again.
func (w *InstallWatcher) blockedPluginDecisionUnchanged(issue AdmissionIssue) bool {
	if issue.Type != string(InstallPlugin) || w.secureClientActive() || w.store == nil {
		return false
	}
	evt := InstallEvent{Type: InstallPlugin, Name: issue.Name, Path: issue.Path, Connector: issue.Connector}
	entry, err := w.store.GetActionForConnector("plugin", evt.Name, w.journalScope(w.eventConnector(evt)))
	if err != nil || entry == nil || entry.Actions.Install != "block" || entry.Actions.Runtime != "disable" ||
		!sameWatcherPath(entry.SourcePath, evt.Path) {
		return false
	}
	baseline, err := w.store.GetTargetSnapshot(string(evt.Type), evt.Path)
	if err != nil || baseline == nil || baseline.ScanID == "" ||
		baseline.ScannerFingerprint != w.scannerFingerprint(evt) {
		return false
	}
	current, err := w.snapshotForEvent(evt)
	return err == nil && current != nil && current.ContentHash == baseline.ContentHash
}

// watchedRoot is a skill or plugin root Run watches and the folder it was
// when the watch was added.
type watchedRoot struct {
	dir, absolute, kind string
	info                os.FileInfo
	failed              bool // the folder now there could not be watched
	checked             time.Time
}

// admitReplacedRoot watches the folders of a skill or plugin root that was
// replaced while the watcher ran and queues what it already holds for
// install admission, as a folder created in the root is (GAP-1315).
func (w *InstallWatcher) admitReplacedRoot(ctx context.Context, fsw *fsnotify.Watcher, root, kind string, watched map[string]struct{}) {
	if kind == "skill" {
		w.watchIncompleteSkillFolders(root)
		w.watchSkillContents(root)
		synced := filepath.Join(root, "synced")
		if depth, ok := w.claudeSyncedDepth(synced); ok && depth == 0 &&
			unlinkedSkillTreePath(root, synced) == nil {
			addDirWatches(fsw, synced, 1, watched)
		}
	} else {
		w.watchExistingPluginFolders(root)
		if w.cacheLayoutPlugins(root) &&
			strings.EqualFold(filepath.Base(filepath.Clean(root)), "cache") {
			addClaudeCacheWatches(fsw, root, watched)
			w.queueExistingClaudePlugins(ctx, root, 0)
			return
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		child := filepath.Join(root, entry.Name())
		if !w.isDirectChildDir(child) {
			continue
		}
		w.recordWatcherEvent(ctx, "create", w.classifyEvent(child).Type.String(), "")
		w.queuePending(child)
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
	admit := ready
	var discarded []string
	if slices.ContainsFunc(ready, func(path string) bool {
		_, _, recursive := w.recursiveSkillRoot(path)
		return recursive
	}) {
		// A move or mkdir sequence can queue both a category and a skill
		// below it. The category expansion sees the current subtree, so
		// admit it once instead of scanning the same skill concurrently.
		sort.Slice(ready, func(i, j int) bool { return len(ready[i]) < len(ready[j]) })
		selected := make(map[string]struct{}, len(ready))
		hasQueuedAncestor := func(path string) bool {
			root, _, recursive := w.recursiveSkillRoot(path)
			if !recursive {
				return false
			}
			for parent := filepath.Dir(path); watcherPathAtOrBelow(parent, root); parent = filepath.Dir(parent) {
				if _, exists := selected[strings.ToLower(filepath.Clean(parent))]; exists {
					return true
				}
				if sameWatcherPath(parent, root) {
					break
				}
			}
			return false
		}
		admit = ready[:0]
		for _, p := range ready {
			delete(w.pending, p)
			if hasQueuedAncestor(p) {
				discarded = append(discarded, p)
				continue
			}
			w.inFlight[p] = true
			selected[strings.ToLower(filepath.Clean(p))] = struct{}{}
			admit = append(admit, p)
		}
		for p := range w.pending {
			if hasQueuedAncestor(p) {
				delete(w.pending, p)
				discarded = append(discarded, p)
			}
		}
	} else {
		// Keep the flat-root and Secure Client ordering unchanged.
		for _, p := range ready {
			delete(w.pending, p)
			w.inFlight[p] = true
		}
	}
	w.mu.Unlock()
	for _, p := range discarded {
		w.state.clear(p)
	}

	for _, path := range admit {
		if _, err := os.Stat(w.addressableAssetPath(path)); err != nil && !w.admitsLinkedAsset(path) {
			w.endAdmission(path)
			continue
		}
		// A folder queued before the plugin copy around it had its
		// manifest is part of that plugin (GAP-0017).
		if root, copied := w.cachePluginCopyRoot(path); copied && !sameWatcherPath(root, path) {
			w.endAdmission(path)
			w.queuePending(root)
			continue
		}
		root, connector, recursive := w.recursiveSkillRoot(path)
		recursive = recursive && !sameWatcherPath(root, path)
		var events []InstallEvent
		if !recursive {
			events = w.pendingInstallEvents(path) // mutable plugin state stays on Run
		}
		w.admissions.Add(1)
		go func() {
			defer w.admissions.Done()
			retry := false
			defer func() {
				w.endAdmission(path)
				if retry && ctx.Err() == nil {
					w.queuePending(path)
				}
			}()
			select {
			case w.liveSlots <- struct{}{}:
			case <-ctx.Done():
				return // no baseline: the next start admits it
			}
			defer func() { <-w.liveSlots }()
			if recursive {
				var err error
				events, err = w.nestedSkillEvents(root, path, connector)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[watch] enumerate moved skill subtree %s: %v\n", path, err)
					if _, statErr := os.Lstat(path); statErr == nil {
						retry = true
					}
					return
				}
			}
			for _, evt := range events {
				if ctx.Err() != nil {
					return
				}
				w.state.set(evt, AdmissionScanning)
				snap := w.admissionSnapshot(evt)
				if snap == nil && evt.Type == InstallPlugin && !w.cfg.Watch.RescanEnabled &&
					!w.secureClientActive() && w.store != nil {
					// Keep the pre-scan identity for a blocked plugin even when
					// periodic rescan is disabled.
					snap, _ = w.snapshotForEvent(evt)
				}
				result := w.runAdmission(ctx, evt)
				if result.Interrupted {
					w.markInterruptedAdmission(evt, snap, w.scannerFingerprint(evt))
				}
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
// the actual nested SKILL.md identities. A failed recursive discovery never
// treats the category as a skill; the live worker retries the subtree.
func (w *InstallWatcher) pendingInstallEvents(path string) []InstallEvent {
	if !w.secureClientActive() {
		for _, root := range w.skillDirs {
			if watcherPathAtOrBelow(path, root) {
				// A direct linked skill is a scan target, but an event below
				// a linked folder must not discover its outside descendants.
				parent := filepath.Dir(path)
				if !watcherPathAtOrBelow(parent, root) {
					parent = root
				}
				if err := unlinkedSkillTreePath(root, parent); err != nil {
					fmt.Fprintf(os.Stderr, "[watch] skill discovery %s: %v\n", path, err)
					return nil
				}
			}
		}
	}
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
	if root, connector, recursive := w.recursiveSkillRoot(path); recursive && !sameWatcherPath(root, path) {
		events, err := w.nestedSkillEvents(root, path, connector)
		if err == nil {
			return events
		}
		return nil
	}
	for _, root := range w.skillDirs {
		discover, _ := hermesSkillsDiscover(root, !w.secureClientActive())
		if discover == nil || !watcherPathAtOrBelow(path, root) {
			continue
		}
		if w.inSkillInstallStaging(root, path, 0) {
			return nil
		}
		entries, err := discover(root, hermesskills.DefaultDirectoryLimit)
		if err != nil {
			return []InstallEvent{fallback}
		}
		out := make([]InstallEvent, 0, len(entries))
		for _, entry := range entries {
			if !watcherPathAtOrBelow(entry.Path, path) || w.inSkillInstallStaging(root, entry.Path, 0) {
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
		// Hermes stores install locks directly under skills/.locks. Discovery
		// found no skill there; do not turn that metadata into a fallback skill.
		if sameWatcherPath(filepath.Dir(path), root) && filepath.Base(path) == ".locks" {
			if info, statErr := os.Lstat(path); statErr == nil && info.IsDir() {
				if _, skillErr := os.Lstat(filepath.Join(path, "SKILL.md")); errors.Is(skillErr, os.ErrNotExist) {
					return nil
				}
			}
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
// markdown file at its top with anything in it. A folder just made with mkdir, being filled in,
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
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".md") &&
			!blankFile(filepath.Join(path, entry.Name())) {
			return false
		}
	}
	return true
}

// blankFile reports whether path is a regular file with nothing but white
// space in it. An editor that creates the file first (Notepad answering
// "create a new file?", touch, an IDE's new-file action) leaves an empty
// SKILL.md that the scanner judged HIGH (Low Analyzability), and the folder
// was quarantined while the user was typing into it (GAP-1105).
func blankFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && len(bytes.TrimSpace(data)) == 0
}

// watchIncompleteSkillFolders waits on the skill folders in root that have no
// markdown file yet when the watcher starts, so a SKILL.md written into one
// later reaches admission (live-created ones are waited on by
// pendingInstallEvents). Hermes roots hold category folders and keep their own
// discovery.
func (w *InstallWatcher) watchIncompleteSkillFolders(root string) {
	if _, _, recursive := w.recursiveSkillRoot(root); recursive {
		return
	}
	if discover, _ := hermesSkillsDiscover(root, !w.secureClientActive()); discover != nil {
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

// changedSkillFolder maps an fsnotify event inside a skill folder to that
// folder: one the watcher waits on (no markdown content yet), or an
// installed skill whose files changed. The watcher used to act only on a
// new folder in the root, so an edited SKILL.md or helper script (an
// in-place append, an editor's atomic rename) waited for the hourly rescan
// or a config reload (GAP-1087). Editor swap and backup files, hidden
// files, Claude's synced account skills and vendor-bundled skills are left
// to the rescan.
func (w *InstallWatcher) changedSkillFolder(path string) (string, bool) {
	parent := filepath.Clean(filepath.Dir(path))
	if _, waiting := w.pluginWaiting[parent]; waiting && w.inSkillRoot(parent) {
		return parent, true
	}
	if editorScratchFile(filepath.Base(path)) {
		return "", false
	}
	if _, synced := w.claudeSyncedDepth(path); synced &&
		(w.secureClientActive() || w.connectorForPath(path) != "cursor") {
		return "", false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	recursiveRoot, _, recursive := w.recursiveSkillRoot(pathAbs)
	for _, root := range w.skillDirs {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if recursive && !sameWatcherPath(rootAbs, recursiveRoot) {
			continue
		}
		rel, err := filepath.Rel(rootAbs, pathAbs)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) < 2 || (strings.HasPrefix(parts[0], ".") && !recursive) {
			return "", false
		}
		skill := filepath.Join(rootAbs, parts[0])
		discover, _ := hermesSkillsDiscover(root, !w.secureClientActive())
		if (recursive && sameWatcherPath(root, recursiveRoot)) ||
			discover != nil {
			// Recursive roots resolve the nearest marked skill, not the
			// category containing it.
			skill = ""
			for dir := filepath.Dir(pathAbs); dir != rootAbs && watcherPathAtOrBelow(dir, rootAbs); dir = filepath.Dir(dir) {
				marked := hasSkillMarker(dir)
				if !recursive {
					info, statErr := os.Stat(filepath.Join(dir, "SKILL.md"))
					marked = statErr == nil && info.Mode().IsRegular()
				}
				if marked {
					skill = dir
					break
				}
			}
			if skill == "" {
				return "", false
			}
		}
		if info, statErr := os.Lstat(skill); statErr != nil || !info.IsDir() || isBundledSkillWatchPath(skill) {
			return "", false
		}
		return skill, true
	}
	return "", false
}

// editorScratchFile reports the swap, lock and backup files editors keep
// next to a file while it is open (vim .x.swp and 4913, emacs .#x and #x#,
// x~), and hidden files: writing them is not a change to the skill.
func editorScratchFile(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") || name == "4913" ||
		(strings.HasPrefix(name, "#") && strings.HasSuffix(name, "#"))
}

// watchSkillContents watches the files of every skill folder already in
// root, so a change to one reaches admission.
func (w *InstallWatcher) watchSkillContents(root string) {
	if w.addContentWatch == nil {
		return
	}
	if _, _, recursive := w.recursiveSkillRoot(root); recursive {
		w.addContentWatch(root)
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
		w.addContentWatch(path)
	}
}

// inSkillRoot reports whether dir is a direct child of a watched skill root.
func (w *InstallWatcher) inSkillRoot(dir string) bool {
	parent, _ := filepath.Abs(filepath.Dir(dir))
	for _, root := range w.skillDirs {
		if rootAbs, _ := filepath.Abs(root); sameWatcherPath(parent, rootAbs) {
			return true
		}
	}
	return false
}

// skillFolderEvent queues the skill folder an event inside it changed. A
// file written into a folder the watcher waits on (an empty SKILL.md that
// now has text) re-checks the folder; a chmod alone changes nothing.
func (w *InstallWatcher) skillFolderEvent(ctx context.Context, event fsnotify.Event, skill string) {
	if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) == 0 {
		return
	}
	if event.Op&fsnotify.Create != 0 && w.addContentWatch != nil {
		if info, err := os.Lstat(event.Name); err == nil && info.IsDir() {
			w.addContentWatch(event.Name)
		}
	}
	w.recordWatcherEvent(ctx, "change", string(InstallSkill), "")
	w.queuePending(skill)
}

func (w *InstallWatcher) classifyEvent(path string) InstallEvent {
	installType := InstallSkill
	name := w.assetEventName(path)
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
	if owner == "codex" && w.cacheLayoutPlugins(path) {
		if pluginID, isPlugin := w.claudePluginIdentity(path); isPlugin {
			return InstallEvent{
				Type:      InstallPlugin,
				Name:      pluginID,
				Path:      path,
				Connector: owner,
				Timestamp: time.Now().UTC(),
			}
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
		case strings.EqualFold(filepath.Base(rootAbs), "cache") && len(parts) == 1 &&
			isCachePluginCopy(pathAbs):
			return parts[0], true
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
	defer func() {
		w.settleAdmissionIssue(evt, res)
		w.releaseHeldOnAdmission(evt, res)
	}()
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
	if res, refused := w.refuseForeignLink(ctx, evt, targetType); refused {
		return res
	}
	// Every effect of this admission (a block, a disable, a release of an
	// earlier block) belongs to one definition: the one the caller
	// snapshotted, or the one found now when it did not snapshot. Each
	// decision is checked against it right before it is enforced or returned:
	// after the policy evaluation, which reads the live policy and the
	// definition on its own, and after the scan, which can run long.
	if evt.Type == InstallMCP && !w.secureClientActive() && evt.definitionHash == "" {
		if hash, err := w.mcpDefinitionHashOf(evt); err == nil {
			evt.definitionHash = hash
		}
	}
	policyID := enforce.PolicyStableID(w.cfg.PolicyDir)
	decisionPolicy := w.admissionPolicySnapshot()
	ctx, admissionTrace := w.startAdmissionTraceV8(ctx, evt, targetType, policyID, decisionPolicy)
	ctx = withDecisionPolicy(ctx, decisionPolicy)
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
	// A root several connectors load applies each one scoped asset rules.
	assetDecision, assetConnector, assetDenying := w.rootAssetPolicy(cfg, evt, connector)
	if assetDecision.Enabled && assetDecision.RawAction == "block" {
		if assetDecision.Action == "block" {
			if w.mcpDefinitionMoved(evt) {
				return w.mcpMovedAdmission(evt)
			}
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=%s source=%s", targetType, assetDecision.Reason, assetDecision.Source))
			// skill list and skill info say the quarantine of a denied
			// asset failed, as they do for a scan verdict; they said
			// quarantined (GAP-0133). An asset that stays in its folder,
			// because the move failed or an operator-restored copy is
			// kept, is held for the connector whose rule denied it too.
			w.journalPolicyDenied(cfg, evt, targetType, w.enforceBlockWith(ctx, evt, true, ""), assetDenying)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: assetDecision.Reason}
			return res
		}
		w.logAssetPolicyWouldBlock(ctx, evt, targetType, assetConnector, assetDecision)
	}
	if res, done := w.legacyAllowPathMismatch(ctx, cfg, evt, targetType); done {
		return res
	}

	// Phase 1: pre-scan evaluation (no scan_result yet). The operator lists
	// come from asset_policy; an allow entry pinned to a source path never
	// transfers to another on-disk asset with the same name (F-2867).
	input := w.admissionInputFor(cfg, evt, targetType, connector)
	out := w.evaluateAdmissionSnapshot(ctx, input, decisionPolicy)
	if w.mcpDefinitionMoved(evt) {
		return w.mcpMovedAdmission(evt)
	}
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
			w.releaseScanFailureBlock(evt, targetType, "admitted without a scan ("+out.Reason+")")
		}
		w.recordAdmission(ctx, "allowed", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
		return res
	}
	// verdict == "scan" → proceed to scanning below

	// A Hermes shipped plugin whose bytes match their pinned digest is not
	// scanned: the block, deny and allow decisions above still apply.
	if w.hermesVendorPlugin(evt) {
		w.logHermesVendorPlugin(evt, targetType)
		w.recordAdmission(ctx, "allowed", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: hermesVendorPluginReason}
		return res
	}

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
	target, err := w.scanTargetFor(evt)
	var result *scanner.ScanResult
	if err == nil {
		result, err = s.Scan(scanCtx, target)
	}
	if err == nil && !w.secureClientActive() {
		err = scanner.JudgeFailure(result)
	}
	if err != nil && ctx.Err() == nil && !w.secureClientActive() {
		if retry, unreadable := w.readableAfterGrant(evt); retry {
			retryCtx, cancelRetry := context.WithTimeout(ctx, w.scanTimeout(evt))
			defer cancelRetry()
			if result, err = s.Scan(retryCtx, target); err == nil {
				err = scanner.JudgeFailure(result)
			}
		} else if unreadable != "" {
			err = fmt.Errorf("%s: %w", unreadable, err)
		}
	}
	if w.mcpDefinitionMoved(evt) {
		// The scan read the server by name when it ran: its verdict is for
		// whatever definition it found, so it is neither enforced nor kept.
		return w.mcpMovedAdmission(evt)
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
		w.logFailedMCPScan(ctx, evt, s.Name(), target, result, err)
		if w.keepsUnverifiedMCPServer(evt, targetType, connector, result, err) {
			// That decision read the live policy and the definition again.
			if w.mcpDefinitionMoved(evt) {
				return w.mcpMovedAdmission(evt)
			}
			return w.keepUnverifiedMCPServer(ctx, evt, targetType, s.Name(), err)
		}
		if assetPathGone(evt) && !w.secureClientActive() {
			// The folder went away before or during its scan (a removed
			// copy, an installer's staging folder): nothing is there to
			// load or move, and a block on the name would keep a later
			// install of the same name disabled (GAP-2118).
			fmt.Fprintf(os.Stderr, "[watch] %s %s: %s is gone; nothing to admit\n", evt.Type, evt.Name, evt.Path)
			w.recordAdmission(ctx, "scan-error", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictScanError,
				Reason: fmt.Sprintf("%s is gone; nothing to admit", evt.Path)}
			return res
		}
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
	// The block an earlier failed scan left is released below, only once the
	// definition this scan was started for has passed every read of the
	// policy and of the server that follows: until then the block stands.
	releaseEarlierFailure := func() {
		w.releaseScanFailureBlock(evt, targetType, "its scan succeeded (the verdict decides)")
	}

	// Phase 3: post-scan evaluation. Re-read the live config so a block or
	// allow added while the scan was running wins.
	decisionPolicy = w.admissionPolicySnapshot()
	admissionTrace.policyDigest, admissionTrace.policyGeneration = decisionPolicy.Digest, decisionPolicy.Generation
	ctx = withDecisionPolicy(ctx, decisionPolicy)
	input = w.admissionInputFor(decisionPolicy.Config, evt, targetType, connector)
	input.ScanResult = &policy.ScanResultInput{
		MaxSeverity:   string(result.MaxSeverity()),
		TotalFindings: len(result.Findings),
		ScannerName:   s.Name(),
		Findings:      toFindingInputs(result.Findings),
	}
	// A default deny or registry_required that a reload switched on while
	// the scan ran applies as the pre-scan check applies it; the lists
	// alone missed it (GAP-1155).
	var postDecision config.AssetPolicyDecision
	var postDenying []string
	if post := decisionPolicy.Config; post != nil {
		postDecision, _, postDenying = w.rootAssetPolicy(post, evt, connector)
	}
	// The policy read above and the input built from it read the definition
	// again, after the scan. Every decision below comes from those reads, so
	// none is published or enforced for a definition the snapshot did not name.
	if w.mcpDefinitionMoved(evt) {
		return w.mcpMovedAdmission(evt)
	}
	if decision := postDecision; decision.Enabled && decision.RawAction == "block" && decision.Action == "block" {
		releaseEarlierFailure()
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s reason=%s source=%s post-scan", targetType, decision.Reason, decision.Source))
		scanID := w.logScanID(ctx, evt, result, "blocked")
		w.journalPolicyDenied(decisionPolicy.Config, evt, targetType, w.enforceBlockWith(ctx, evt, true, ""), postDenying)
		w.recordAdmission(ctx, "blocked", targetType)
		res = AdmissionResult{
			ScanID: scanID,
			Event:  evt, Verdict: VerdictBlocked, Reason: decision.Reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "block",
		}
		return res
	}
	if input.BlockListed() {
		releaseEarlierFailure()
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
		releaseEarlierFailure()
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

	policy.WarnJudgeOnlyPluginHigh(decisionPolicy.Config, connector, &input)
	out = w.evaluateAdmissionSnapshot(ctx, input, decisionPolicy)
	if w.mcpDefinitionMoved(evt) {
		return w.mcpMovedAdmission(evt)
	}
	releaseEarlierFailure()
	w.applyPostScanEnforcement(ctx, out, evt, targetType, result, s.Name())
	scanID := w.logScanID(ctx, evt, result, out.Verdict)
	w.recordAdmission(ctx, out.Verdict, targetType)
	if evt.Type != InstallMCP {
		switch v := toVerdict(out.Verdict); v {
		case VerdictClean, VerdictAllowed, VerdictWarning:
			// A reinstall or rescan that admission now allows replaces
			// this watcher's own earlier rejection of the asset (GAP-1911).
			w.releaseSupersededRejection(evt, targetType, v)
		}
	}
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
	// A remembered definition is the one the event asks about, even when the
	// agent config lists another definition under the same name.
	entry := evt.remembered
	if entry == nil {
		var err error
		if entry, err = w.lookupMCPServer(evt); err != nil {
			return in
		}
	}
	in.URL, in.Command, in.Args, in.Transport = entry.URL, entry.Command, entry.Args, entry.Transport
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
			blockReason := fmt.Sprintf(autoBlockReasonPrefix+"%s findings (scanner=%s)", result.MaxSeverity(), scannerName)
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
			rowType, rowName := journalTarget(evt, targetType)

			if installAction == "block" {
				_ = w.store.SetActionFieldForConnector(rowType, rowName, scope, "install", "block", blockReason)
			}
			_ = w.store.SetSourcePathForConnector(rowType, rowName, scope, evt.Path)

			enforcement := map[string]string{
				"source_path": evt.Path,
				"install":     installAction,
				"runtime":     runtimeAction,
				"file":        fileAction,
			}

			secureClient := w.secureClientActive()
			if fileAction == "quarantine" && !retainRestored && secureClient {
				_ = w.store.SetActionFieldForConnector(rowType, rowName, scope, "file", "quarantine", blockReason)
			}
			if runtimeAction == "block" {
				_ = w.store.SetRuntimeDisableForConnector(rowType, rowName, scope, evt.Path, blockReason)
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
					if err == nil {
						_ = w.store.SetActionFieldForConnector(rowType, rowName, scope, "file", "quarantine", blockReason)
					} else {
						w.journalFailedQuarantine(evt, targetType, err)
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
			// (GAP-0623). An enrolled user's server starts as that user, in
			// a folder the hook enumerator checks as the user: the gateway
			// does not look into the project (#1164).
			if entry.Project != "" && entry.URL == "" && entry.RunAsSID == "" {
				if info, statErr := os.Stat(entry.Project); statErr == nil && info.IsDir() {
					ms.Project, ms.Connector = entry.Project, entry.Connector
				}
			}
		}
		return ms

	case InstallPlugin:
		plugin := scanner.NewPluginScanner(cfg.Scanners.PluginScanner)
		plugin.Connector = w.eventConnector(evt)
		plugin.LLM = cfg.ResolveLLM("scanners.plugin")
		plugin.Policy = pluginScannerPolicy(cfg, plugin.Connector)
		plugin.DisableVendorIdentity = cfg.SecureClientIntegration()
		return plugin
	default:
		return nil
	}
}

// pluginScannerPolicy carries the effective strict tier to the plugin scanner.
func pluginScannerPolicy(cfg *config.Config, connector string) string {
	if cfg == nil || cfg.SecureClientIntegration() {
		return ""
	}
	if cfg.HookPolicyTierForConnector(connector) == "strict" {
		return "strict"
	}
	return ""
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
	denied := unreadableAssetEntry(w.addressableAssetPath(evt.Path))
	if denied == "" {
		return false, ""
	}
	grantErr := enforce.GrantAssetRead(string(evt.Type), evt.Path)
	if grantErr == nil {
		if denied = unreadableAssetEntry(w.addressableAssetPath(evt.Path)); denied == "" {
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

// logAssetPolicyWouldBlock records an asset_policy rule (a default deny,
// registry_required) that would refuse the asset in mode action and, in mode
// observe, lets it through: the asset-policy row the hooks write for an MCP
// server, so the administrator can pilot a skill catalog from the rows too
// (GAP-0964). Secure Client keeps the rows of main (issue #1092).
func (w *InstallWatcher) logAssetPolicyWouldBlock(ctx context.Context, evt InstallEvent, targetType, connector string, d config.AssetPolicyDecision) {
	if w.logger == nil || !d.WouldBlock || w.secureClientActive() {
		return
	}
	_ = w.logger.LogEventCtx(ctx, audit.Event{
		Action:    string(audit.ActionAssetPolicy),
		Target:    targetType + ":" + evt.Name,
		Actor:     "defenseclaw",
		Connector: connector,
		Severity:  "INFO",
		Details: fmt.Sprintf("action=%s source=%s registry_status=%s registry_configured=%v surface=watcher connector=%s would_block=true path=%s reason=%s",
			d.Action, d.Source, d.RegistryStatus, d.RegistryConfigured, connector, evt.Path, d.Reason),
	})
}

// recordScanFailureBlock journals the install block and runtime disable of
// an asset whose scan failed, for the connector that holds it.
// autoBlockReasonPrefix leads the journal reason of the block and runtime
// disable the watcher writes for a rejected verdict (applyPostScanEnforcement).
const autoBlockReasonPrefix = "auto-block: watch detected "

// hasRecoverableMCPBlock checks only this watcher's scoped rejection or
// scanner-failure block. A manual hold or row for another definition must not
// turn a periodic rescan into a recovery admission.
func (w *InstallWatcher) hasRecoverableMCPBlock(evt InstallEvent) bool {
	if evt.Type != InstallMCP || w.store == nil {
		return false
	}
	rowType, rowName := journalTarget(evt, string(InstallMCP))
	entry, err := w.store.GetActionForConnector(rowType, rowName, w.journalScope(w.eventConnector(evt)))
	return err == nil && entry != nil && (entry.Actions.Runtime == "disable" || entry.Actions.Install == "block") &&
		(strings.HasPrefix(entry.Reason, autoBlockReasonPrefix) || strings.HasPrefix(entry.Reason, scanFailureReason)) &&
		(entry.SourcePath == "" || sameWatcherPath(entry.SourcePath, evt.Path))
}

// releaseSupersededMCPRejection lifts the install block and runtime disable
// that the watcher's own rejection of an MCP server left, once admission
// allowed a changed definition of that server. The rejection was for the
// old definition; a restored benign server stayed refused with the old
// reason after its clean admission (GAP-0266). Only the watcher's own
// rejection of this server is lifted: an operator block, a row of another
// server and a block written for a failed scan (releaseScanFailureBlock)
// stay, and so does a bare-name row another listed server of the same name
// shares (a release there could free that server's rejection). Secure
// Client never readmits a changed server (issue #1092).
func (w *InstallWatcher) releaseSupersededMCPRejection(evt InstallEvent, verdict Verdict) {
	if evt.Type != InstallMCP {
		return
	}
	w.releaseSupersededRejection(evt, string(InstallMCP), verdict)
}

// releaseSupersededRejection is releaseSupersededMCPRejection for every
// asset type. A skill or plugin the watcher rejected (for example under an
// explicit admission high=block) kept that install block and runtime disable
// after the administrator relaxed the setting and the user reinstalled it:
// the new admission warned, but the old auto-block row still refused it
// (GAP-1911). The same rule applies: only the watcher's own rejection of
// this asset at this path is lifted when admission now allows it.
func (w *InstallWatcher) releaseSupersededRejection(evt InstallEvent, targetType string, verdict Verdict) {
	if w.store == nil || w.secureClientActive() {
		return
	}
	rowType, name := journalTarget(evt, targetType)
	scope := w.journalScope(w.eventConnector(evt))
	entry, err := w.store.GetActionForConnector(rowType, name, scope)
	if err != nil || entry == nil || entry.Actions.IsEmpty() || !strings.HasPrefix(entry.Reason, autoBlockReasonPrefix) ||
		(entry.SourcePath != "" && !sameWatcherPath(entry.SourcePath, evt.Path)) {
		return
	}
	if evt.Type == InstallMCP && name != evt.Path && w.mcpNameSharedByAnotherServer(evt) {
		fmt.Fprintf(os.Stderr, "[watch] mcp %s: its changed definition was admitted (%s), but another server of that name shares its block, which stays\n",
			evt.Name, verdict)
		return
	}
	var cleared []string
	for _, field := range []struct{ name, value string }{
		{"file", entry.Actions.File}, {"install", entry.Actions.Install}, {"runtime", entry.Actions.Runtime},
	} {
		if field.value == "" {
			continue
		}
		if err := w.store.ClearActionFieldForConnector(rowType, name, scope, field.name); err == nil {
			cleared = append(cleared, field.name+"="+field.value)
		}
	}
	if len(cleared) == 0 {
		return
	}
	if evt.Type == InstallMCP {
		fmt.Fprintf(os.Stderr, "[watch] mcp %s: admission allowed its changed definition (%s); its earlier rejection no longer applies\n", evt.Name, verdict)
		_ = w.logger.LogAction(string(audit.ActionEnable), evt.Path,
			fmt.Sprintf("type=mcp released: admission allowed its changed definition (verdict=%s); cleared %s connector=%s",
				verdict, strings.Join(cleared, " "), scope))
		return
	}
	fmt.Fprintf(os.Stderr, "[watch] %s %s: admission now allows it (%s); the watcher's earlier rejection no longer applies\n", targetType, evt.Name, verdict)
	_ = w.logger.LogAction(string(audit.ActionEnable), evt.Path,
		fmt.Sprintf("type=%s released: admission now allows it (verdict=%s); cleared %s connector=%s",
			targetType, verdict, strings.Join(cleared, " "), scope))
}

// mcpNameSharedByAnotherServer reports whether another listed MCP server
// has the name of evt, so a journal row kept under the bare name may hold
// that server's verdict too. A listing that fails says so (fail closed).
func (w *InstallWatcher) mcpNameSharedByAnotherServer(evt InstallEvent) bool {
	servers, err := w.readMCPServers()
	if err != nil {
		return true
	}
	for _, server := range servers {
		if server.Name == evt.Name && MCPEventPath(server) != evt.Path {
			return true
		}
	}
	return false
}

// keepsUnverifiedMCPServer reports an MCP server whose scan ended without a
// verdict and that scanners.mcp_scanner.unverified_server warn keeps, as mcp
// set adds it (GAP-1195): the scan did not finish (a timeout, a launcher or
// scanner that exited, an unreachable server) or the scanner refused the
// definition in a tier that fails open (GAP-0775), no finding was reported,
// and the live policy neither refuses unverified servers (explicit block) nor
// blocks this server. Secure Client keeps its fail-closed admission.
func (w *InstallWatcher) keepsUnverifiedMCPServer(evt InstallEvent, targetType, connector string, result *scanner.ScanResult, err error) bool {
	if evt.Type != InstallMCP || w.secureClientActive() || (result != nil && len(result.Findings) > 0) {
		return false
	}
	cfg := w.admissionPolicySnapshot().Config
	if cfg == nil || cfg.MCPUnverifiedServerBlocks() {
		return false
	}
	// A definition the scanner refuses (a launcher or address it never
	// starts or dials) is a server DefenseClaw cannot scan, not a malicious
	// one: the OSS default and permissive tiers keep it with a warning, and
	// the strict tier and every managed profile still refuse it (fail
	// closed). A completed scan that finds something never reaches here.
	if scanner.MCPScanRefused(err) && cfg.MCPAdmissionFailsClosed(connector) {
		return false
	}
	decision := cfg.EvaluateAssetPolicy(w.withMCPDefinition(cfg, evt, config.AssetPolicyInput{
		TargetType: targetType, Name: evt.Name, DeclaredNames: declaredAssetNames(cfg, evt),
		Connector: connector, SourcePath: evt.Path, RuntimeSurface: "watcher",
	}))
	if decision.Enabled && decision.RawAction == "block" && decision.Action == "block" {
		return false
	}
	return !w.admissionInputFor(cfg, evt, targetType, connector).BlockListed()
}

// logFailedMCPScan records an MCP admission scan that did not finish as a
// failed scan row, so mcp list shows the server's last scan failed instead
// of an older clean result (GAP-1869). The Secure Client profile keeps the
// scan log of main.
func (w *InstallWatcher) logFailedMCPScan(ctx context.Context, evt InstallEvent, scannerName, target string, result *scanner.ScanResult, err error) {
	if evt.Type != InstallMCP || w.secureClientActive() || err == nil {
		return
	}
	failed := &scanner.ScanResult{
		Scanner:    scannerName,
		Target:     target,
		Timestamp:  time.Now(),
		TargetType: scanner.InferTargetType(scannerName),
	}
	if result != nil {
		copied := *result
		failed = &copied
		if failed.Target == "" {
			failed.Target = target
		}
	}
	if failed.Target == "" {
		return
	}
	if failed.ExitCode == 0 {
		failed.ExitCode = -1
	}
	if failed.ScanError == "" {
		failed.ScanError = err.Error()
	}
	_ = w.logScan(ctx, evt, failed, "scan-error")
}

// unverifiedMCPReason leads the reason of an MCP server kept unverified.
const unverifiedMCPReason = "scan did not finish, kept unverified (scanners.mcp_scanner.unverified_server: warn): "

// unscannableMCPReason leads the reason of an MCP server the scanner refuses
// (a launcher or address it never starts or dials) that a fail-open tier
// keeps with a warning. Strict and managed profiles block it instead.
const unscannableMCPReason = "cannot be scanned, kept with a warning (fail-closed only in the strict tier and managed profiles): "

// keptUnscannedMCPReason reports the reason of an MCP server kept after a
// scan that did not finish or that the scanner refused.
func keptUnscannedMCPReason(reason string) bool {
	return strings.HasPrefix(reason, unverifiedMCPReason) || strings.HasPrefix(reason, unscannableMCPReason)
}

// keepUnverifiedMCPServer keeps an MCP server whose scan did not finish: a
// MEDIUM audit row says so, a block an earlier failed scan left is released,
// and its marked baseline makes the rescan retry admission until a scan decides.
func (w *InstallWatcher) keepUnverifiedMCPServer(ctx context.Context, evt InstallEvent, targetType, scannerName string, err error) AdmissionResult {
	reason := unverifiedMCPReason + err.Error()
	cause := "kept unverified (scanners.mcp_scanner.unverified_server: warn)"
	if scanner.MCPScanRefused(err) {
		reason = unscannableMCPReason + err.Error()
		cause = "kept with a warning: the server cannot be scanned and this profile fails open"
	}
	w.releaseScanFailureBlock(evt, targetType, cause)
	_ = w.logger.LogEventCtx(ctx, audit.Event{
		Action:   string(audit.ActionInstallAllowed),
		Target:   evt.Path,
		Actor:    "defenseclaw",
		Details:  fmt.Sprintf("type=%s reason=unverified scanner=%s %s", targetType, scannerName, reason),
		Severity: "MEDIUM",
	})
	fmt.Fprintf(os.Stderr, "[watch] %s %s: %s\n", evt.Type, evt.Name, reason)
	w.recordAdmission(ctx, "scan-error", targetType)
	return AdmissionResult{Event: evt, Verdict: VerdictScanError, Reason: reason}
}

func (w *InstallWatcher) recordScanFailureBlock(evt InstallEvent, targetType, reason string) {
	if w.store == nil {
		return
	}
	scope := w.journalScope(w.eventConnector(evt))
	rowType, rowName := journalTarget(evt, targetType)
	_ = w.store.SetActionFieldForConnector(rowType, rowName, scope, "install", "block", reason)
	// One statement records the runtime disable, the source path and the
	// path that decided it (the provenance an account row is read by).
	_ = w.store.SetRuntimeDisableForConnector(rowType, rowName, scope, evt.Path, reason)
}

// releaseScanFailureBlock clears the block and runtime disable a failed scan
// of this asset left, once a scan of it succeeds (or admission decides it
// without one; cause says how), and writes an enable audit row naming the
// cleared block, as releaseSupersededRejection does (GAP-0289). The Secure
// Client profile journals no such block.
func (w *InstallWatcher) releaseScanFailureBlock(evt InstallEvent, targetType, cause string) {
	if w.secureClientActive() || w.store == nil {
		return
	}
	scope := w.journalScope(w.eventConnector(evt))
	rowType, rowName := journalTarget(evt, targetType)
	entry, err := w.store.GetActionForConnector(rowType, rowName, scope)
	if err != nil || entry == nil || !strings.HasPrefix(entry.Reason, scanFailureReason) ||
		(entry.SourcePath != "" && !sameWatcherPath(entry.SourcePath, evt.Path) && !blockedPathGone(entry.SourcePath)) {
		return
	}
	var cleared []string
	for _, field := range []struct{ name, value string }{
		{"install", entry.Actions.Install}, {"runtime", entry.Actions.Runtime},
	} {
		if field.value == "" {
			continue
		}
		if err := w.store.ClearActionFieldForConnector(rowType, rowName, scope, field.name); err == nil {
			cleared = append(cleared, field.name+"="+field.value)
		}
	}
	if len(cleared) == 0 || w.logger == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "[watch] %s %s: %s; the block its failed scan left no longer applies\n", targetType, evt.Name, cause)
	_ = w.logger.LogAction(string(audit.ActionEnable), evt.Path,
		fmt.Sprintf("type=%s released: %s; cleared the scan-failure block %s connector=%s",
			targetType, cause, strings.Join(cleared, " "), scope))
}

// blockedPathGone reports a scan-failure block recorded for a folder that no
// longer exists (an installer's staging copy, a removed copy): a successful
// scan of the same name at its real place lifts it (GAP-2118).
func blockedPathGone(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// journalFailedQuarantine records on the journal that the quarantine of a
// blocked asset failed (err), or that its link was removed: install block,
// with the reason skill list and skill info show.
//
// A root several connectors load is journaled for the owner and for each
// connector in also (the one whose rule denied the asset), so the denying
// connector is never left without the action.
func (w *InstallWatcher) journalFailedQuarantine(evt InstallEvent, targetType string, err error, also ...string) {
	if w.store == nil {
		return
	}
	reason := quarantineFailedReason + err.Error()
	if errors.Is(err, errLinkRemoved) {
		reason = err.Error()
	}
	rowType, rowName := journalTarget(evt, targetType)
	scopes := []string{w.journalScope(w.eventConnector(evt))}
	for _, connector := range also {
		if scope := w.journalScope(connector); !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	for _, scope := range scopes {
		_ = w.store.SetActionFieldForConnector(rowType, rowName, scope, "install", "block", reason)
	}
}

// policyDenialMarkPrefix opens the tag that ends the journal reason of a hold
// journalPolicyDenied wrote. The tag lists the fields of the row the hold
// set and the copies of the asset it was written for, so releasePolicyHolds
// lifts those fields, and only once the last of those copies is allowed; an
// install block or runtime disable that was on the row for another reason is
// not in the list and stays. A journal row is keyed by the asset's name, not
// by its path, so the copies are recorded in the tag: the row's source path
// belongs to an earlier block, or to whichever copy was judged last.
const policyDenialMarkPrefix = " [asset policy: "

// policyHeldCopiesMark separates, in the tag, the held fields from the copies.
const policyHeldCopiesMark = " copies="

// policyDenialSep follows, in the reason of a row the hold shares with an
// earlier runtime disable, the reason of that earlier block; releasing the
// hold puts it back.
const policyDenialSep = " | asset policy hold: "

// retainedPolicyReason leads the reason of a hold on an operator-restored
// copy that stays in its folder although a connector rule denies it.
const retainedPolicyReason = "a restored copy stays in its folder while an asset policy rule denies it"

func policyDenialMark(fields, copies []string) string {
	return policyDenialMarkPrefix + strings.Join(fields, ",") + policyHeldCopiesMark + strings.Join(copies, ",") + "]"
}

// parsePolicyHold returns the fields and the copies a journal reason records
// as held by a policy hold, or nil when the reason carries no tag.
func parsePolicyHold(reason string) (fields, copies []string) {
	i := strings.LastIndex(reason, policyDenialMarkPrefix)
	if i < 0 || !strings.HasSuffix(reason, "]") {
		return nil, nil
	}
	body, list, found := strings.Cut(strings.TrimSuffix(reason[i+len(policyDenialMarkPrefix):], "]"), policyHeldCopiesMark)
	if found && list != "" {
		copies = strings.Split(list, ",")
	}
	return strings.Split(body, ","), copies
}

// policyCopyKey names one copy of an asset in a hold tag: its absolute,
// cleaned path in the spelling it was written with, encoded so that no path
// can end or split the tag. The spelling is kept because the path is shown to
// the operator; copies are matched with samePolicyCopy, which folds case on
// Windows, as sameWatcherPath does.
func policyCopyKey(path string) string {
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		abs = strings.TrimSpace(path)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(filepath.Clean(abs)))
}

// samePolicyCopy reports whether two tag keys name the same copy. Windows
// paths differ only by case when they name one folder, and a tag written by an
// earlier build holds the folded spelling.
func samePolicyCopy(a, b string) bool {
	return policyCopyKeysEqual(a, b, runtime.GOOS == "windows")
}

func policyCopyKeysEqual(a, b string, foldCase bool) bool {
	if a == b {
		return true
	}
	rawA, errA := base64.RawURLEncoding.DecodeString(a)
	rawB, errB := base64.RawURLEncoding.DecodeString(b)
	return foldCase && errA == nil && errB == nil && strings.EqualFold(string(rawA), string(rawB))
}

func hasPolicyCopy(keys []string, key string) bool {
	return slices.ContainsFunc(keys, func(other string) bool { return samePolicyCopy(other, key) })
}

// livePolicyCopies are the copies of a tag other than skip whose folder is
// not absent; a copy that is gone leaves nothing to run and holds nothing. A
// copy this process cannot look at (a private parent folder) is present,
// unknown, and stays.
func livePolicyCopies(copies []string, skip string) []string {
	var live []string
	for _, key := range copies {
		raw, err := base64.RawURLEncoding.DecodeString(key)
		if err == nil && !samePolicyCopy(key, skip) && !policyCopyGone(string(raw)) && !hasPolicyCopy(live, key) {
			live = append(live, key)
		}
	}
	return live
}

// policyPriorReason is the reason of the block a hold shares its row with
// (policyDenialSep), or "".
func policyPriorReason(reason string) string {
	if i := strings.Index(reason, policyDenialSep); i >= 0 {
		return reason[:i]
	}
	return ""
}

func actionFieldValue(entry *audit.ActionEntry, field string) string {
	if entry == nil {
		return ""
	}
	switch field {
	case "install":
		return entry.Actions.Install
	case "runtime":
		return entry.Actions.Runtime
	case "file":
		return entry.Actions.File
	}
	return ""
}

// policyRuntimeScope is the journal row that carries a connector's runtime
// disable from a policy hold: the connector's own row. OpenClaw's install
// journal is the global row (journalScope), which every other connector's
// runtime check falls back to, so a runtime disable written there would block
// an unrelated connector's skill of the same name.
func policyRuntimeScope(connector string) string {
	return strings.ToLower(strings.TrimSpace(connector))
}

// policyHoldScopes are the journal rows a policy hold of evt may sit in: the
// install row and the runtime row of the owner and of every consumer.
func (w *InstallWatcher) policyHoldScopes(evt InstallEvent) []string {
	var scopes []string
	for _, connector := range w.rootConsumersOf(evt, w.eventConnector(evt)) {
		for _, scope := range []string{w.journalScope(connector), policyRuntimeScope(connector)} {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}
	return scopes
}

// journalPolicyDenied records, after enforceBlockWith (err is its result) on
// an asset an asset_policy rule denied (cfg is the policy generation that
// decided the denial, so the tier that holds the root owner is the one that
// denied, not the config the process started with), that the asset is still in its
// folder: because the quarantine failed (err), or because the files of an
// operator restore are kept while the install block stands. Every connector
// in denying (each one whose rule denied the copy, as each loads it) gets the
// install block and, on its own row, the runtime disable. A root owner whose
// own rules allow the copy is not held for another connector denial in the
// balanced and permissive tiers, where it runs the ordinary skill; the strict
// tier and a managed deployment hold it too.
// Without the runtime disable a denial by the
// default (default_action deny) rule, which the hook evaluates only when
// runtime_detection is on, left the surviving skill callable. A block already
// on a row for another reason (install, runtime or file) is left as it is: not
// claimed, not re-pinned to this copy, not lifted with the hold. A runtime
// enable is no block and the hold replaces it. releasePolicyHolds lifts what the hold set when the denial goes; an
// operator enable clears it too. A removed link, or an asset that is gone,
// leaves nothing to run and no runtime disable.
func (w *InstallWatcher) journalPolicyDenied(cfg *config.Config, evt InstallEvent, targetType string, err error, denying []string) {
	if w.store == nil || w.secureClientActive() {
		return
	}
	var reason string
	switch {
	case errors.Is(err, errLinkRemoved):
		w.journalFailedQuarantine(evt, targetType, err, denying...)
		return
	case err != nil:
		reason = quarantineFailedReason + err.Error()
	case (evt.Type == InstallSkill || evt.Type == InstallPlugin) && assetStillThere(evt.Path):
		reason = retainedPolicyReason
	default:
		return
	}
	type holdRow struct {
		scope  string
		fields []string
	}
	var rows []holdRow
	add := func(scope, field string) {
		for i := range rows {
			if rows[i].scope == scope {
				rows[i].fields = append(rows[i].fields, field)
				return
			}
		}
		rows = append(rows, holdRow{scope, []string{field}})
	}
	owner := w.eventConnector(evt)
	var connectors []string
	if len(denying) == 0 || PolicyHoldStrict(cfg, owner) {
		connectors = []string{owner}
	}
	for _, connector := range denying {
		if connector != "" && !containsFold(connectors, connector) {
			connectors = append(connectors, connector)
		}
	}
	var installScopes []string
	for _, connector := range connectors {
		if scope := w.journalScope(connector); !slices.Contains(installScopes, scope) {
			installScopes = append(installScopes, scope)
			add(scope, "install")
		}
	}
	for _, connector := range connectors {
		if scope := policyRuntimeScope(connector); scope != "" {
			add(scope, "runtime")
		}
	}
	name := evt.Name
	for _, row := range rows {
		prev, _ := w.store.GetActionForConnector(targetType, name, row.scope)
		owned, prevCopies := parsePolicyHold(reasonOf(prev))
		copies := append(livePolicyCopies(prevCopies, policyCopyKey(evt.Path)), policyCopyKey(evt.Path))
		// A field already at its protective value that no hold of ours set is an
		// earlier block (an operator, a scan verdict, a failed quarantine). The
		// hold does not claim it, rebind its source path or lift it later. Any
		// other value, a runtime enable among them, is not a block and the hold
		// replaces it.
		independent := func(field string) bool {
			value := actionFieldValue(prev, field)
			return value != "" && value == policyProtectiveValue(field) && !slices.Contains(owned, field)
		}
		earlier := false
		for _, field := range []string{"install", "runtime", "file"} {
			earlier = earlier || independent(field)
		}
		// An earlier block pinned to another copy keeps that path, since an
		// allow rule for this copy would otherwise lift it. The row then holds
		// only the runtime disable (it covers every copy of the name), and holds
		// nothing when that disable is the earlier block.
		pinnedElsewhere := earlier && prev.SourcePath != "" && !sameWatcherPath(prev.SourcePath, evt.Path)
		var claim []string
		for _, field := range row.fields {
			if !independent(field) && (!pinnedElsewhere || field == "runtime") {
				claim = append(claim, field)
			}
		}
		for _, field := range owned {
			if !slices.Contains(claim, field) && actionFieldValue(prev, field) != "" {
				claim = append(claim, field)
			}
		}
		if len(claim) == 0 {
			continue
		}
		rowReason := reason + policyDenialMark(claim, copies)
		if prior := policyPriorReason(reasonOf(prev)); prior != "" {
			rowReason = prior + policyDenialSep + rowReason
		} else if earlier && owned == nil && reasonOf(prev) != "" {
			rowReason = prev.Reason + policyDenialSep + rowReason
		}
		for _, field := range claim {
			value := "block"
			if field == "runtime" {
				value = "disable"
			}
			_ = w.store.SetActionFieldForConnector(targetType, name, row.scope, field, value, rowReason)
		}
		if !pinnedElsewhere {
			_ = w.store.SetSourcePathForConnector(targetType, name, row.scope, evt.Path)
		}
	}
}

// policyProtectiveValue is the value of a journal action field that blocks
// the asset, or empty for a field that holds no block.
func policyProtectiveValue(field string) string {
	switch field {
	case "install":
		return "block"
	case "runtime":
		return "disable"
	case "file":
		return "quarantine"
	}
	return ""
}

func reasonOf(entry *audit.ActionEntry) string {
	if entry == nil {
		return ""
	}
	return entry.Reason
}

func assetStillThere(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// policyCopyGone reports a held copy whose folder is absent, as opposed to
// one this process cannot look at.
func policyCopyGone(path string) bool {
	_, err := os.Lstat(path)
	return pathAbsent(err)
}

// policyHeldScopes are the journal rows of the owner and of every consumer of
// the root holding evt that hold something a journalPolicyDenied wrote for
// this copy. A row pinned to another copy by an earlier block still counts:
// the hold is the copy's own.
func (w *InstallWatcher) policyHeldScopes(evt InstallEvent) []string {
	if w.secureClientActive() || w.store == nil || (evt.Type != InstallSkill && evt.Type != InstallPlugin) {
		return nil
	}
	var scopes []string
	for _, scope := range w.policyHoldScopes(evt) {
		entry, err := w.store.GetActionForConnector(string(evt.Type), evt.Name, scope)
		if err != nil || entry == nil {
			continue
		}
		fields, copies := parsePolicyHold(entry.Reason)
		if !hasPolicyCopy(copies, policyCopyKey(evt.Path)) {
			continue
		}
		for _, field := range fields {
			if actionFieldValue(entry, field) != "" {
				scopes = append(scopes, scope)
				break
			}
		}
	}
	return scopes
}

// releasePolicyHolds lifts, from the owner and from every consumer, what a
// policy denial set on an asset that stayed in its folder, once no connector
// rule denies it: an allow rule for it (a global one or one scoped to the
// denying connector) or a policy that no longer denies. Without it an allow
// rule cleared only the owner row and the allowed skill stayed blocked for
// the denying connector. A block or disable that was on a row before the
// hold stays, and so does the hold itself while another copy of the same name
// is still denied.
func (w *InstallWatcher) releasePolicyHolds(evt InstallEvent) {
	for _, scope := range w.policyHeldScopes(evt) {
		entry, err := w.store.GetActionForConnector(string(evt.Type), evt.Name, scope)
		if err != nil || entry == nil {
			continue
		}
		fields, copies := parsePolicyHold(entry.Reason)
		if others := livePolicyCopies(copies, policyCopyKey(evt.Path)); len(others) > 0 {
			// Another copy of the name is still denied: its hold stays whole,
			// and only this copy leaves the tag.
			reason := entry.Reason[:strings.LastIndex(entry.Reason, policyDenialMarkPrefix)] + policyDenialMark(fields, others)
			for _, field := range fields {
				if value := actionFieldValue(entry, field); value != "" {
					_ = w.store.SetActionFieldForConnector(string(evt.Type), evt.Name, scope, field, value, reason)
				}
			}
			continue
		}
		var cleared []string
		for _, field := range fields {
			if actionFieldValue(entry, field) == "" {
				continue
			}
			if err := w.store.ClearActionFieldForConnector(string(evt.Type), evt.Name, scope, field); err == nil {
				cleared = append(cleared, field)
			}
		}
		if len(cleared) == 0 {
			continue
		}
		if rest, _ := w.store.GetActionForConnector(string(evt.Type), evt.Name, scope); rest != nil {
			if prior := policyPriorReason(entry.Reason); prior != "" {
				for _, field := range []string{"runtime", "install", "file"} {
					if value := actionFieldValue(rest, field); value != "" {
						_ = w.store.SetActionFieldForConnector(string(evt.Type), evt.Name, scope, field, value, prior)
						break
					}
				}
			}
		}
		_ = w.logger.LogAction(string(audit.ActionEnable), evt.Path,
			fmt.Sprintf("type=%s released: no asset policy rule denies it; cleared %s connector=%s", evt.Type, strings.Join(cleared, " "), scope))
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
	if evt.Type == InstallPlugin && !w.secureClientActive() {
		// A rescan and a filesystem event can share one quarantine record and
		// stage. Keep their filesystem and journal transitions in order.
		w.quarantineMoveMu.Lock()
		defer w.quarantineMoveMu.Unlock()
		if _, err := os.Lstat(evt.Path); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
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
	physicalName := w.assetEventName(evt.Path)
	quarantinePath, quarantineRoots, quarantineRoot := evt.Path, w.sourceRootsFor(evt.Type), w.cfg.QuarantineDir
	if !w.secureClientActive() {
		quarantinePath, quarantineRoots = w.resolvedLinkedRoot(quarantinePath, quarantineRoots)
		quarantinePath, quarantineRoots, quarantineRoot = addressableQuarantinePaths(quarantinePath, quarantineRoots, quarantineRoot)
	}
	plan, err := enforce.NewAssetQuarantinePlan(
		quarantineRoot, quarantineRoots, evt.Type.String(),
		physicalName, connector, quarantinePath,
	)
	if err != nil {
		w.emitQuarantineFailure(ctx, evt, err)
		return err
	}
	if evt.Type == InstallPlugin && !w.secureClientActive() &&
		!strings.Contains(evt.Name, "/") && evt.Name != physicalName {
		plan, err = plan.WithPluginQuarantineName(evt.Name)
		if err != nil {
			w.emitQuarantineFailure(ctx, evt, err)
			return err
		}
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
		if quarantineUnmaterialized(plan, err, record.CreatedAt.Equal(record.UpdatedAt)) {
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

// resolvedLinkedRoot maps path, below a watched root that is reached through
// a link (a ~/.claude that points into a dotfiles folder), to the same entry
// below the root's resolved folder, and adds that folder to roots. The
// quarantine planner refuses a source with a linked ancestor, so such a
// skill was scanned and watcher-blocked but never moved, and the agent kept
// loading it (GAP-1088). A path that is already below a resolved root keeps
// it (a restore of what was quarantined from there). The resolved folder
// must be in the home of the account that owns the watched root, so a link
// cannot have the gateway move another account's files.
func (w *InstallWatcher) resolvedLinkedRoot(path string, roots []string) (string, []string) {
	for _, root := range roots {
		resolved, ok := w.resolvedRootOf(root)
		if !ok {
			continue
		}
		withResolved := append(append([]string(nil), roots...), resolved)
		if watcherPathAtOrBelow(path, resolved) {
			return path, withResolved
		}
		if !watcherPathAtOrBelow(path, root) {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}
		return filepath.Join(resolved, rel), withResolved
	}
	return path, roots
}

// resolvedRootOf is the physical folder behind a watched root that is reached
// through a link, when that folder is in the home of the account that owns
// the root. False for a plain root, an unsafe link or another account's
// folder.
func (w *InstallWatcher) resolvedRootOf(root string) (string, bool) {
	resolved, err := filepath.EvalSymlinks(root)
	if !w.secureClientActive() {
		resolved, err = skillrootsafe.Resolve(root, watcherEvalSymlinks)
	}
	if err != nil || sameWatcherPath(resolved, root) {
		return "", false
	}
	linkOwner, linkOwned := w.ownerOf(root)
	targetOwner, targetOwned := w.ownerOf(resolved)
	if linkOwned != targetOwned || linkOwner.Home != targetOwner.Home {
		return "", false
	}
	return resolved, true
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
	if err != nil || entry == nil ||
		(entry.SourcePath != "" && !sameWatcherPath(entry.SourcePath, evt.Path)) {
		return
	}
	var cleared []string
	held, _ := parsePolicyHold(entry.Reason)
	for field, value := range map[string]string{"runtime": entry.Actions.Runtime, "install": entry.Actions.Install} {
		// A field a policy hold set is lifted by releasePolicyHolds, which
		// keeps it while another copy of the name is still denied.
		if value == "" || slices.Contains(held, field) {
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
	if err != nil || entry == nil || (entry.Actions.Runtime == "" && entry.Actions.Install == "") ||
		(entry.SourcePath != "" && !sameWatcherPath(entry.SourcePath, evt.Path)) {
		return false
	}
	cfg := w.liveConfig()
	out := w.evaluateAdmission(ctx, w.admissionInputFor(cfg, evt, string(evt.Type), connector))
	return out != nil && out.Verdict == "allowed" && w.allowedAuditReason(out.Reason) == "allow-listed"
}

// policyDenies reports whether a connector rule that loads evt's root denies
// it under the live config.
func (w *InstallWatcher) policyDenies(evt InstallEvent) bool {
	decision, _, _ := w.rootAssetPolicy(w.liveConfig(), evt, w.eventConnector(evt))
	return decision.Enabled && decision.RawAction == "block" && decision.Action == "block"
}

// policyHoldReleases reports a skill or plugin whose owner or consumer row
// still holds it after an asset-policy denial although no connector rule
// denies it now, so the rescan admits it again and lifts the hold.
func (w *InstallWatcher) policyHoldReleases(evt InstallEvent) bool {
	return len(w.policyHeldScopes(evt)) > 0 && !w.policyDenies(evt)
}

// releaseHeldOnAdmission lifts a policy hold once admission has reached a
// verdict that lets the asset run: a scan that has not finished, one that was
// interrupted, and a block all keep it, since until then nothing but the hold
// stops a skill that stayed in its folder (the hook evaluates the default
// skill rules only with runtime_detection on).
func (w *InstallWatcher) releaseHeldOnAdmission(evt InstallEvent, res AdmissionResult) {
	if res.Interrupted {
		return
	}
	switch res.Verdict {
	case VerdictAllowed, VerdictClean, VerdictWarning:
	default:
		return
	}
	if len(w.policyHeldScopes(evt)) > 0 && !w.policyDenies(evt) {
		w.releasePolicyHolds(evt)
	}
}

// quarantinedCopyIsBack reports a skill or plugin at a path that holds an
// active quarantine of it: the original was moved out and a copy is back.
func (w *InstallWatcher) quarantinedCopyIsBack(ctx context.Context, evt InstallEvent) bool {
	if w.secureClientActive() || w.store == nil || (evt.Type != InstallSkill && evt.Type != InstallPlugin) {
		return false
	}
	records, err := w.quarantineRecordsForName(ctx, evt.Type.String(), evt.Name, w.eventConnector(evt))
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

// linkedAssetScanTarget limits the gateway's read authority to the watched
// folders of the account that holds the link. A link may be resolved for
// scanning only when its final target stays in one of this asset type's
// watched roots and, on a computer that watches several accounts, in the
// home of the account whose folder holds the link: other users' skill
// folders are watched roots too, and a standard user's junction into one
// had the gateway scan that user's content and report it under the planter
// (GAP-1188).
var errLinkedAssetOutsideRoots = errors.New("linked asset target is outside the watched folders of its account")

func (w *InstallWatcher) linkedAssetScanTarget(evt InstallEvent) (string, error) {
	target := linkedAssetTarget(evt.Path)
	linkOwner, linkOwned := w.ownerOf(evt.Path)
	targetOwner, targetOwned := w.ownerOf(target)
	if linkOwned != targetOwned || linkOwner.Home != targetOwner.Home {
		return "", errLinkedAssetOutsideRoots
	}
	roots := w.sourceRootsFor(evt.Type)
	if !w.secureClientActive() {
		// The link target is a physical path; a watched root reached
		// through a link (~/.claude -> dotfiles) holds it at its resolved
		// folder, as a plain root does (GAP-0906).
		for _, root := range roots {
			if resolved, ok := w.resolvedRootOf(root); ok {
				roots = append(slices.Clone(roots), resolved)
			}
		}
	}
	for _, root := range roots {
		if watcherPathAtOrBelow(target, root) {
			return target, nil
		}
		// OpenClaw installs npm plugins in a managed project beside its
		// extensions folder and links the extension entry to that package.
		// Read only that project's package tree for an extension entry.
		if evt.Type == InstallPlugin && w.eventConnector(evt) == "openclaw" &&
			filepath.Base(root) == "extensions" && sameWatcherPath(filepath.Dir(evt.Path), root) &&
			watcherPathAtOrBelow(target, filepath.Join(filepath.Dir(root), "npm", "projects")) {
			return target, nil
		}
	}
	return "", errLinkedAssetOutsideRoots
}

// foreignLink reports a skill or plugin that is a link whose target lies
// outside the watched folders of the account that holds it, and that
// target. Nothing is read through such a link.
func (w *InstallWatcher) foreignLink(evt InstallEvent) (string, bool) {
	if (evt.Type != InstallSkill && evt.Type != InstallPlugin) || !w.admitsLinkedAsset(evt.Path) {
		return "", false
	}
	if _, err := w.linkedAssetScanTarget(evt); !errors.Is(err, errLinkedAssetOutsideRoots) {
		return "", false
	}
	return linkedAssetTarget(evt.Path), true
}

// refuseForeignLink refuses a link into a folder its account does not own,
// such as another user's skills folder, without reading it: no scan runs,
// no finding about the other folder is reported under the planter, and the
// verdict says the same whatever the target holds. The link is taken out of
// the folder (never the target), and the install-rejected row names the
// link, its owner and where it points (GAP-1188).
func (w *InstallWatcher) refuseForeignLink(ctx context.Context, evt InstallEvent, targetType string) (AdmissionResult, bool) {
	target, foreign := w.foreignLink(evt)
	if !foreign {
		return AdmissionResult{}, false
	}
	account := "this account"
	if owner, ok := w.ownerOf(evt.Path); ok && strings.TrimSpace(owner.Name) != "" {
		account = owner.Name
	}
	reason := fmt.Sprintf("the %s is a link to %s, outside the watched %s folders of %s; it was not scanned and the link is removed",
		targetType, target, targetType, account)
	_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
		fmt.Sprintf("type=%s reason=link-outside-own-folders user=%s target=%q", targetType, account, target))
	if err := w.enforceBlockWith(ctx, evt, false, reason); err != nil && !errors.Is(err, errLinkRemoved) {
		// The link stays: refuse it at runtime until it is gone.
		w.recordScanFailureBlock(evt, targetType, scanFailureReason+reason)
	}
	w.recordAdmission(ctx, "blocked", targetType)
	return AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: reason}, true
}

// removeLinkedAsset takes a skill or plugin that is a symlink or Windows
// junction out of the watched folder: the link is removed and the folder it
// points to is never touched (GAP-0394). Before, quarantine refused the link
// and only gateway.log said so, while the skill read as quarantined.
func (w *InstallWatcher) removeLinkedAsset(ctx context.Context, evt InstallEvent) error {
	// The link is removed itself, never followed; a root reached through a
	// link is addressed by its resolved folder, because the removal refuses a
	// linked ancestor (GAP-0906).
	linkPath, roots := w.resolvedLinkedRoot(evt.Path, w.sourceRootsFor(evt.Type))
	target, err := enforce.RemoveLinkedAsset(roots, evt.Type.String(), linkPath)
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

func (w *InstallWatcher) quarantineRecordsForName(
	ctx context.Context, targetType, targetName, connector string,
) ([]audit.QuarantineRecord, error) {
	if !w.secureClientActive() && runtime.GOOS == "windows" && strings.HasSuffix(targetName, " ") {
		return w.store.ListQuarantineRecordsForConnectorExact(ctx, targetType, targetName, connector)
	}
	return w.store.ListQuarantineRecordsForConnector(ctx, targetType, targetName, connector)
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
	if w.secureClientActive() || runtime.GOOS != "windows" || !strings.HasSuffix(targetName, " ") {
		targetName = strings.TrimSpace(targetName)
	}
	connector = strings.TrimSpace(connector)
	if targetType != InstallSkill.String() && targetType != InstallPlugin.String() {
		return fmt.Errorf("watcher: unsupported restore target type %q", targetType)
	}
	records, err := w.quarantineRecordsForName(ctx, targetType, targetName, connector)
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
	requestedRestorePath, boundRestorePath := restorePath, record.RestorePath
	if w.secureClientActive() || runtime.GOOS != "windows" || !strings.HasSuffix(targetName, " ") {
		requestedRestorePath = strings.TrimSpace(requestedRestorePath)
		boundRestorePath = strings.TrimSpace(boundRestorePath)
	}
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
	restoreRoots := w.sourceRootsFor(InstallType(record.TargetType))
	quarantineRoot := w.cfg.QuarantineDir
	if !w.secureClientActive() {
		restorePath, restoreRoots = w.resolvedLinkedRoot(restorePath, restoreRoots)
		restorePath, restoreRoots, quarantineRoot = addressableQuarantinePaths(restorePath, restoreRoots, quarantineRoot)
	}
	plan := enforce.AssetRestorePlan{
		RecordID: record.ID, TargetType: record.TargetType,
		TargetName:     w.assetEventName(record.QuarantinePath),
		QuarantineRoot: quarantineRoot, QuarantinePath: record.QuarantinePath,
		RestorePath: restorePath, AllowedRoots: restoreRoots,
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
		if entry.SourcePath != "" && (sameWatcherPath(entry.SourcePath, evt.Path) ||
			(!w.secureClientActive() && sameAddressableWatcherPath(entry.SourcePath, evt.Path))) {
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
		if root, copied := w.cachePluginCopyRoot(child); copied {
			if !sameWatcherPath(root, child) {
				continue
			}
		} else if depth+1 < 3 {
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
		if !isPluginStagingFolder(first) {
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

// isPluginStagingFolder names a staging folder in a plugin cache: Claude
// Code's temp_local_<id>, and the .dclaw-stage-<name>-<random> folder that
// "defenseclaw plugin install" copies a plugin into, scans and decides
// itself before it moves the copy to cache/<name> (GAP-0017).
func isPluginStagingFolder(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"temp_local_", ".dclaw-stage-"} {
		if strings.HasPrefix(lower, prefix) && len(lower) > len(prefix) {
			return true
		}
	}
	return false
}

// inSkillInstallStaging reports a path at or below a ".dclaw-stage-<name>-*"
// folder directly in the skill root root: "defenseclaw skill install" copies
// a skill there, scans and decides it for each connector, then moves it into
// place or removes it. Hermes discovery walks hidden folders, so the watcher
// scanned that private copy under ~/.hermes/skills (the other roots skip
// hidden folders), found it gone and left a fail-closed block on the skill
// name that kept a later admitted install disabled (GAP-2118). grace, when
// set, is how long the folder is left alone; one that stays longer is
// scanned. The Secure Client profile keeps the earlier behaviour.
func (w *InstallWatcher) inSkillInstallStaging(root, path string, grace time.Duration) bool {
	if w.secureClientActive() {
		return false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	first := strings.FieldsFunc(relative, func(r rune) bool { return r == '/' || r == '\\' })[0]
	lower := strings.ToLower(first)
	if !strings.HasPrefix(lower, skillStagePrefix) || len(lower) == len(skillStagePrefix) {
		return false
	}
	if grace <= 0 {
		return true
	}
	info, statErr := os.Lstat(filepath.Join(rootAbs, first))
	return statErr == nil && time.Since(info.ModTime()) < grace
}

// skillStagePrefix leads the private staging folder of "defenseclaw skill
// install" (cli/defenseclaw/commands/cmd_skill.py _stage_skill_install).
const skillStagePrefix = ".dclaw-stage-"

// assetPathGone reports a skill or plugin whose folder no longer exists:
// there is nothing an agent can load, so a failed scan of it is no verdict
// on the name (GAP-2118).
func assetPathGone(evt InstallEvent) bool {
	if evt.Type != InstallSkill && evt.Type != InstallPlugin {
		return false
	}
	_, err := os.Lstat(evt.Path)
	return errors.Is(err, fs.ErrNotExist)
}

// isCachePluginCopy reports a folder directly in a plugin cache that holds a
// plugin manifest: a whole plugin copied there ("defenseclaw plugin install"
// writes cache/<name>), not a <marketplace> folder of <plugin>/<version>
// folders.
func isCachePluginCopy(path string) bool {
	return !strings.HasPrefix(filepath.Base(path), ".") && hasPluginManifest(path)
}

// cachePluginCopyRoot returns the plugin copy (isCachePluginCopy) that path
// is or lies in, for a cache-layout plugin root. Its sub-folders (skills,
// skills/<skill>, .git, ...) are part of that one plugin: the watcher read
// them as <marketplace>/<plugin>/<version> folders and blocked each for a
// missing manifest (GAP-0017). The whole copy is scanned as one plugin.
func (w *InstallWatcher) cachePluginCopyRoot(path string) (string, bool) {
	if w.secureClientActive() || !w.cacheLayoutPlugins(path) {
		return "", false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", false
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
		candidate := filepath.Join(rootAbs, first)
		if isCachePluginCopy(candidate) {
			return candidate, true
		}
		return "", false
	}
	return "", false
}

// cacheLayoutPlugins reports whether the plugin root that holds path is read
// as a <marketplace>/<plugin>/<version> cache when it is named cache: Claude
// Code's plugins/cache, and Codex's $CODEX_HOME/plugins/cache. The rescan and
// the live watcher read Codex's cache one level deep, so its marketplace
// folder (openai-curated-remote) was scanned as a plugin and a fresh init
// raised a HIGH MANIFEST-MISSING alert on it (GAP-1573). The Secure Client
// deployment keeps the Codex watcher it had.
func (w *InstallWatcher) cacheLayoutPlugins(path string) bool {
	switch w.connectorForPath(path) {
	case "claudecode":
		return true
	case "codex":
		return !w.secureClientActive()
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
	if _, err := os.Lstat(w.addressableAssetPath(evt.Path)); err != nil && evt.Type != InstallMCP {
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
// could not fully quarantine. Publication can precede a source-cleanup
// failure, so the audit must not claim either location's current state.
func (w *InstallWatcher) emitQuarantineFailure(ctx context.Context, evt InstallEvent, err error) {
	// A removal the hook guardian deferred to the user's next sign-in is the
	// guardian's to finish; status reports it from the guardian's list.
	if w != nil && !w.secureClientActive() && !errors.Is(err, enforce.ErrQuarantineRemovalDeferred) {
		w.admissionNotes.Store(evt.Path, AdmissionIssue{Kind: AdmissionNotQuarantined, Detail: err.Error()})
	}
	// A rejected asset with a link inside is not moved, because quarantine does
	// not follow links, and its files stay where they are. The runtime disable
	// is applied by the gateway after admission, so the watcher cannot say it
	// was applied: the alert names the reason and keeps the HIGH severity of a
	// failed quarantine until the disable is confirmed elsewhere (GAP-0826).
	// Secure Client keeps the failed-quarantine record unchanged.
	alertTitle := "Quarantine failed; inspect the source and quarantine copy"
	auditDetail := fmt.Sprintf("type=%s quarantine failed; inspect the source and quarantine copy: %v", evt.Type, err)
	if errors.Is(err, enforce.ErrLinkedAssetContent) && w != nil && !w.secureClientActive() {
		alertTitle = "Rejected " + evt.Type.String() + " is not quarantined: its files contain a link, which quarantine does not follow; the files stay in place, confirm the asset is disabled in its runtime"
		auditDetail = fmt.Sprintf("type=%s not quarantined, its files contain a link and stay in place; confirm the asset is disabled in its runtime: %v", evt.Type, err)
	}
	if w != nil && w.logger != nil {
		_ = w.logger.RecordQuarantineActionMetric(ctx, "move_in", "error")
		if !w.secureClientActive() {
			envelope := audit.EnvelopeFromContext(ctx)
			envelope.Connector = w.eventConnector(evt)
			alertCtx := audit.ContextWithEnvelope(ctx, envelope)
			_ = w.logger.LogAlertCtx(alertCtx, "watcher", "HIGH", alertTitle, map[string]any{
				"asset_type": evt.Type.String(), "asset_name": evt.Name,
				"path": evt.Path, "error": err.Error(), "connector": w.eventConnector(evt),
			})
		}
		_ = w.logger.LogEventCtx(ctx, audit.Event{
			Action:   string(audit.ActionWatcherBlock),
			Target:   evt.Path,
			Actor:    "defenseclaw",
			Details:  auditDetail,
			Severity: "HIGH",
		})
	}
	fmt.Fprintf(os.Stderr, "[watch] quarantine %s: %v\n", evt.Path, err)
}

// quarantineUnmaterialized reports that a failed quarantine (err) left no
// copy its pending record must keep: the destination does not exist, or it
// cannot be inspected (a quarantine folder the gateway may not enter) and
// the record is the one this attempt opened (fresh) for a move that failed
// before it published a copy. The record of such a quarantine is rolled
// back; kept, it made skill info say quarantined for files that never moved
// (GAP-0133). An uncertain destination of a published copy, or of a record
// an earlier attempt opened, keeps its record: the copy may be there, and
// the record is what restores it. The source still being in place proves
// nothing, as a published copy whose source removal failed leaves both.
func quarantineUnmaterialized(plan enforce.AssetQuarantinePlan, err error, fresh bool) bool {
	_, statErr := os.Lstat(plan.QuarantinePath)
	if os.IsNotExist(statErr) {
		return true
	}
	return statErr != nil && fresh && !errors.Is(err, enforce.ErrQuarantinePublished)
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
	_ = w.logger.LogEnforcementQuarantineApplied(ctx, event, quarantineAppliedInput(ctx, evt, destPath))
}

// quarantineAppliedInput is the asset.quarantined input of a quarantine,
// stamped with the policy of the admission decision that ordered it when
// ctx carries one (withDecisionPolicy).
func quarantineAppliedInput(ctx context.Context, evt InstallEvent, destPath string) audit.EnforcementQuarantineAppliedInput {
	input := audit.EnforcementQuarantineAppliedInput{
		EnforcementID:   uuid.NewString(),
		RequestedAction: "quarantine",
		EffectiveAction: "quarantine",
		Initiator:       "defenseclaw",
		ResultingState:  "quarantined",
		AssetID:         evt.Name,
		AssetType:       evt.Type.String(),
		SourcePath:      evt.Path,
		DestinationPath: destPath,
	}
	if stamp, ok := ctx.Value(decisionPolicyKey{}).(decisionPolicyStamp); ok {
		input.PolicyStamped, input.PolicyDigest, input.PolicyGeneration = true, stamp.digest, stamp.generation
	}
	return input
}

type decisionPolicyKey struct{}

type decisionPolicyStamp struct {
	digest     observability.Optional[string]
	generation observability.Optional[int64]
}

// withDecisionPolicy records on ctx the policy generation an admission
// decision used, so the quarantine it orders names that generation and not
// one a reload applied while the files were being moved (p0 GAP-1000).
func withDecisionPolicy(ctx context.Context, snapshot AdmissionPolicySnapshot) context.Context {
	return context.WithValue(ctx, decisionPolicyKey{}, decisionPolicyStamp{snapshot.Digest, snapshot.Generation})
}

// isDirectChildDir returns true if path is a directory and a direct child
// of one of the watched skill or MCP directories. Files and nested
// subdirectories inside a skill are ignored — a skill is always a top-level
// directory under a skill dir.
func (w *InstallWatcher) isDirectChildDir(path string) bool {
	info, err := os.Stat(w.addressableAssetPath(path))
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
	if w.cacheLayoutPlugins(path) {
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
			RuleID:   f.RuleID,
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

// vendorSystemRoots hold the machine-wide folders agents read administrator
// policy and skills from: Codex /etc/codex, Cursor /etc/cursor, Copilot
// /etc/github-copilot, Claude Code and OpenCode under /Library/Application
// Support, and %ProgramData% on Windows. The watcher only observes them.
// Creating one changes the agent's own behavior: Codex treats an existing
// /etc/codex as an administrator policy layer and pauses with "organization
// settings could not be loaded" when it cannot read it, which is what a
// gateway running as root did by creating /etc/codex (mode 0700) for its
// /etc/codex/skills watch. An absent vendor system folder is watched once an
// administrator or installer creates it, like an agent-owned folder
// (GAP-2354). Tests substitute a private root.
var vendorSystemRoots = gatewayconnector.DefaultVendorSystemRoots()

// errAbsentVendorSystemDir reports a watch root under vendorSystemRoots that
// does not exist; the watcher never creates it.
var errAbsentVendorSystemDir = errors.New("vendor system folder is absent; the watcher does not create it")

// isAbsentVendorSystemDir reports whether dir does not exist and lies under
// one of vendorSystemRoots. The absolute path is compared without resolving
// symlinks, so /etc/codex on macOS (where /etc links to /private/etc) matches
// through either spelling.
func isAbsentVendorSystemDir(dir string) bool {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	if _, err := os.Lstat(absolute); !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return underVendorSystemRoot(absolute)
}

func underVendorSystemRoot(absolute string) bool {
	return gatewayconnector.UnderVendorSystemRoot(absolute, vendorSystemRoots)
}

// errWatchDirNotCreated reads "create dir": the watcher could not create a
// missing root (for example under a parent only an administrator may write).
var errWatchDirNotCreated = errors.New("create dir")

// ensureAndWatch creates and watches an asset root after validating any
// account-owned links in its existing path. It returns folders it created.
func ensureAndWatch(fsw *fsnotify.Watcher, dir string) ([]string, error) {
	return ensureAndWatchWithCheck(fsw, dir, true)
}

// ensureAndWatchLegacy retains the existing Secure Client watch behavior.
func ensureAndWatchLegacy(fsw *fsnotify.Watcher, dir string) ([]string, error) {
	return ensureAndWatchWithCheck(fsw, dir, false)
}

func ensureAndWatchWithCheck(fsw *fsnotify.Watcher, dir string, checkLinks bool) ([]string, error) {
	var created []string
	if isAbsentVendorSystemDir(dir) {
		return nil, errAbsentVendorSystemDir
	}
	if checkLinks {
		for current := filepath.Clean(dir); ; current = filepath.Dir(current) {
			if _, err := os.Lstat(current); err == nil {
				if _, resolveErr := skillrootsafe.Resolve(current, watcherEvalSymlinks); resolveErr != nil {
					return nil, linkedRootRefusal(dir, resolveErr)
				}
				break
			} else if !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%w: inspect skill root %s: %v", errWatchDirNotCreated, dir, err)
			}
			parent := filepath.Dir(current)
			if parent == current {
				return nil, fmt.Errorf("unavailable skill root: %s", dir)
			}
		}
	}
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
		return nil, fmt.Errorf("%w: %w", errWatchDirNotCreated, err)
	}
	if checkLinks {
		if err := unlinkedSkillTreePath(dir, dir); err != nil {
			return created, err
		}
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
// skillContentWatchDepth bounds how far below a skill folder its files are
// watched (SKILL.md, scripts/, scripts/lib/...).
const skillContentWatchDepth = 3

// addSkillContentWatches watches dir and its sub-folders down to
// skillContentWatchDepth, skipping links, hidden folders and dependency or
// cache trees, whose churn says nothing about the skill.
func addSkillContentWatches(fsw *fsnotify.Watcher, dir string, watched map[string]struct{}) {
	dir = filepath.Clean(dir)
	_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == dir {
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
		if path != dir {
			name := entry.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "__pycache__" {
				return fs.SkipDir
			}
			if rel, relErr := filepath.Rel(dir, path); relErr != nil ||
				len(strings.Split(rel, string(filepath.Separator))) > skillContentWatchDepth {
				return fs.SkipDir
			}
		}
		key := strings.ToLower(path)
		if _, exists := watched[key]; !exists {
			if addErr := fsw.Add(path); addErr == nil {
				watched[key] = struct{}{}
			}
		}
		return nil
	})
}

func addDirWatches(
	fsw *fsnotify.Watcher,
	root string,
	maxDepth int,
	watched map[string]struct{},
) {
	addDirWatchesWithRootLink(fsw, root, maxDepth, watched, true)
}

// Secure Client retains the plain WalkDir behavior for a linked final root.
func addDirWatchesLegacy(
	fsw *fsnotify.Watcher,
	root string,
	maxDepth int,
	watched map[string]struct{},
) {
	addDirWatchesWithRootLink(fsw, root, maxDepth, watched, false)
}

func addDirWatchesWithRootLink(
	fsw *fsnotify.Watcher,
	root string,
	maxDepth int,
	watched map[string]struct{},
	allowRootLink bool,
) {
	root = filepath.Clean(root)
	walkRoot := root
	if allowRootLink {
		var err error
		walkRoot, err = trustedWalkRoot(root)
		if err != nil {
			return
		}
	}
	_ = filepath.WalkDir(walkRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == walkRoot {
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
		relative, relErr := filepath.Rel(walkRoot, path)
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
		logical, mapErr := logicalWalkPath(root, walkRoot, path)
		if mapErr != nil {
			return fs.SkipDir
		}
		key := strings.ToLower(filepath.Clean(logical))
		if _, exists := watched[key]; !exists {
			if addErr := fsw.Add(logical); addErr == nil {
				watched[key] = struct{}{}
			}
		}
		return nil
	})
}
