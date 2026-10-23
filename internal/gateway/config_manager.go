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

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const configReloadDebounce = 500 * time.Millisecond

const configReloadSnapshotAttempts = 3

// A temporary permission refusal during an atomic lifecycle rollback can
// outlive the fsnotify event that triggered it. Retry without another write.
const configReloadPermissionRetry = 5 * time.Second

// configReloadInFlight is held from the first file event of a burst until
// its reload is applied or rejected. `guardrail profile explain` waits for
// it (awaitConfigReload): an administrator who writes the configuration and
// asks at once got the answer of the previous configuration, then the new
// one a second later (GAP-0307).
var configReloadInFlight = &configReloadGate{}

// configReloadExplainWait bounds that wait; a reload normally takes well
// under a second after the debounce.
const configReloadExplainWait = 10 * time.Second

// configReloadGate counts the config bursts seen and not yet applied.
type configReloadGate struct {
	mu     sync.Mutex
	active int
	idle   chan struct{}
}

func (g *configReloadGate) begin() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == 0 {
		g.idle = make(chan struct{})
	}
	g.active++
}

func (g *configReloadGate) settle() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == 0 {
		return
	}
	if g.active--; g.active == 0 {
		close(g.idle)
		g.idle = nil
	}
}

// wait returns once no burst is pending, or after max; false on timeout.
func (g *configReloadGate) wait(max time.Duration) bool {
	g.mu.Lock()
	idle := g.idle
	g.mu.Unlock()
	if idle == nil {
		return true
	}
	timer := time.NewTimer(max)
	defer timer.Stop()
	select {
	case <-idle:
		return true
	case <-timer.C:
		return false
	}
}

// awaitConfigReload serves next once the configuration written last is
// applied, or after configReloadExplainWait.
func awaitConfigReload(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configReloadInFlight.wait(configReloadExplainWait)
		next(w, r)
	}
}

const configReloadStartupQuietPeriod = 25 * time.Millisecond

// configDiffAssets is the Changed entry of a reload that no config key
// caused: a referenced asset (rule pack, Rego module) changed on disk.
const configDiffAssets = "assets"

// errGenerationUnchanged reports a rebuild that matches the live generation;
// nothing is swapped.
var errGenerationUnchanged = errors.New("config reload: generation unchanged")

type ConfigDiff struct {
	Changed         []string
	RestartRequired []string
}

// configReloadSource is the stable, exact file snapshot used to construct a
// reload candidate. For schema v8, compiledV8 was derived from these exact raw
// bytes and then augmented only with release-owned destinations from the
// effective Config candidate before diff/apply. Keeping it private prevents
// callers from treating the source (which may contain secrets) as a logging or
// API payload.
type configReloadSource struct {
	sourceName string
	raw        []byte
	compiledV8 *config.ObservabilityV8CompiledConfig
	// proveUnchanged permits a managed rebuild solely to prove that config
	// and assets still match the published generation, without publishing.
	proveUnchanged bool
}

type configSnapshotApplyFunc func(
	ctx context.Context,
	oldCfg, newCfg *config.Config,
	diff ConfigDiff,
	source configReloadSource,
) error

type configFileSnapshot struct {
	raw  []byte
	info os.FileInfo
}

type configSnapshotLoader func(string, []byte) (*config.Config, error)
type configFileSnapshotReader func(string) (configFileSnapshot, error)

type ConfigManager struct {
	path          string
	applySnapshot configSnapshotApplyFunc
	logger        *audit.Logger
	health        *SidecarHealth
	loadSnapshot  configSnapshotLoader
	readSnapshot  configFileSnapshotReader
	v8PlanDigest  string
	v8Plan        *config.ObservabilityV8Plan
	// appliedRaw is the config.yaml bytes of the last applied or reconciled
	// generation, so an applied change can name the paths that changed.
	// Guarded by mu.
	appliedRaw []byte
	// appliedGeneration is the config.generation.json generation of the last
	// applied bytes (appliedGenerationKnown), so config.change.applied names a
	// writer only for a single generation (GAP-0318). Guarded by mu.
	appliedGeneration      uint64
	appliedGenerationKnown bool
	afterWatchAdded        func()
	observabilityV8        hookLifecycleMetricV8Runtime
	// assetDirs lists the directories of the assets the live generation
	// references (generation.assetDirs); the watcher follows them so an
	// edited rule pack or Rego module rebuilds the generation.
	assetDirs func() []string
	// assetFiles lists its single-file assets (generation.assetFiles); the
	// watcher follows their directories and matches these exact paths.
	assetFiles func() []string
	// candidateAssets lists the asset directories and files a candidate
	// configuration references. While a reload stands rejected the watcher
	// follows those of the rejected candidate too, so repairing an asset
	// only it references rebuilds the generation (GAP-0881).
	candidateAssets func(*config.Config) (dirs, files []string)
	rejectedAssets  atomic.Pointer[candidateAssetSet]
	// assetWatchFailures are the asset folders the watcher could not watch
	// (GAP-0879); config health is degraded while there are any.
	healthMu           sync.Mutex
	lastConfigHealth   configHealthReport
	assetWatchFailures []string
	// startupSource is the digest of the bytes the gateway booted from; the
	// startup reconcile skips its reload while the file still holds them.
	startupSource [sha256.Size]byte
	startupKnown  bool

	// envConfigPath is the AVC-authored env_config.json (see
	// config.ResolveDefaultEnvConfigPath). When set, Reload overlays
	// cisco_ai_defense_endpoint from that file on top of the
	// config.yaml value before diffing, and Run adds the file's parent
	// directory to the fsnotify watch set so a late-arriving
	// env_config.json triggers a reload. Empty means "no overlay" —
	// this is what opensource / non-managed installs pass.
	//
	// Stored via atomic.Pointer so SetEnvConfigPath is safe to call
	// concurrently with the Run loop's readers (classify() and the
	// Reload overlay). The Provider interface's doc contract says
	// SetEnvConfigPath after Run has started must "still be picked up
	// on the next Reload"; plain field access would race on that path.
	envConfigPath atomic.Pointer[string]

	// envOverlayApplied flips to true the first time we successfully
	// apply an endpoint from env_config.json. Once true, a subsequent
	// "file missing" during Reload is treated the same as a malformed
	// overlay — we RETAIN the previously-active endpoint and surface
	// a health error, rather than silently reverting to the
	// config.yaml default. Data-residency compliance requires an
	// audit trail; a legitimate AVC-driven region change comes via
	// a REWRITTEN file, not a deletion.
	envOverlayApplied atomic.Bool

	// rejected is set (under mu) when the last reload this manager ran was
	// refused, and cleared by the next one that builds. While it stands the
	// next reload rebuilds the generation even without a config or asset
	// diff, since the repair is exactly what the diff cannot see.
	rejected                bool
	permissionRetry         bool
	permissionRetryInterval time.Duration

	current atomic.Value // *config.Config
	gen     atomic.Uint64
	mu      sync.Mutex
}

// candidateAssetSet is what candidateAssets listed for a rejected candidate.
type candidateAssetSet struct {
	dirs, files []string
}

// configHealthReport is the config health a reload last reported.
type configHealthReport struct {
	set     bool
	state   SubsystemState
	lastErr string
	details map[string]interface{}
}

// setConfigHealth reports config health, degraded while asset folders are
// not watched (setAssetWatchFailures).
func (m *ConfigManager) setConfigHealth(state SubsystemState, lastErr string, details map[string]interface{}) {
	if m == nil || m.health == nil {
		return
	}
	m.healthMu.Lock()
	m.lastConfigHealth = configHealthReport{set: true, state: state, lastErr: lastErr, details: details}
	failures := m.assetWatchFailures
	m.healthMu.Unlock()
	m.health.SetConfig(withAssetWatchFailures(state, lastErr, details, failures))
}

// setAssetWatchFailures records the asset folders the watcher could not
// watch and reports config health again when they change.
func (m *ConfigManager) setAssetWatchFailures(failures []string) {
	if m == nil {
		return
	}
	m.healthMu.Lock()
	if slices.Equal(m.assetWatchFailures, failures) {
		m.healthMu.Unlock()
		return
	}
	m.assetWatchFailures = slices.Clone(failures)
	last := m.lastConfigHealth
	m.healthMu.Unlock()
	if len(failures) > 0 {
		fmt.Fprintf(os.Stderr, "[config] WARNING: cannot watch policy asset folders %s; their edits are checked every 30 s\n",
			strings.Join(failures, ", "))
	}
	if m.health != nil && last.set {
		m.health.SetConfig(withAssetWatchFailures(last.state, last.lastErr, last.details, failures))
	}
}

func withAssetWatchFailures(state SubsystemState, lastErr string, details map[string]interface{},
	failures []string) (SubsystemState, string, map[string]interface{}) {
	if len(failures) == 0 || state != StateRunning {
		return state, lastErr, details
	}
	degraded := make(map[string]interface{}, len(details)+1)
	for key, value := range details {
		degraded[key] = value
	}
	degraded["asset_watch_failed"] = slices.Clone(failures)
	return StateDegraded, "cannot watch policy asset folders " + strings.Join(failures, ", ") +
		"; their edits are checked every 30 s", degraded
}

// noteRejectedCandidateAssets keeps the assets of a rejected candidate
// watched until a reload builds (GAP-0881).
func (m *ConfigManager) noteRejectedCandidateAssets(candidate *config.Config) {
	if m.candidateAssets == nil || candidate == nil {
		return
	}
	dirs, files := m.candidateAssets(candidate)
	m.rejectedAssets.Store(&candidateAssetSet{dirs: dirs, files: files})
}

func (m *ConfigManager) bindObservabilityV8(runtime hookLifecycleMetricV8Runtime) {
	if m == nil {
		return
	}
	// Construction binds this before the watcher goroutine starts. Tests may
	// leave it nil to exercise the config transaction independently.
	m.observabilityV8 = runtime
}

func (m *ConfigManager) bindInitialObservabilityV8Plan(plan *config.ObservabilityV8Plan) {
	if m == nil || plan == nil {
		return
	}
	m.v8Plan = plan
	m.v8PlanDigest = plan.Digest()
}

func (m *ConfigManager) recordLoadError(ctx context.Context, errorType string) {
	if m == nil || m.observabilityV8 == nil {
		return
	}
	recordConfigLoadErrorV8(ctx, m.observabilityV8, errorType)
}

// getEnvConfigPath returns the current env_config.json overlay path, or
// "" if none has been set. Safe for concurrent use with SetEnvConfigPath.
func (m *ConfigManager) getEnvConfigPath() string {
	if m == nil {
		return ""
	}
	if p := m.envConfigPath.Load(); p != nil {
		return *p
	}
	return ""
}

// loadRuntimeConfigCandidate decodes a config snapshot for activation. A
// config_version 8 file is migrated in memory first (read-only), so it runs
// as `defenseclaw migrate` would write it: its data.json admission and
// thresholds and, on a per-user install, its audit.db block/allow entries
// keep applying. A file whose migration fails is refused.
func loadRuntimeConfigCandidate(source string, raw []byte) (*config.Config, error) {
	legacyV8 := config.NeedsMigrationV9(raw)
	migrated, exportKey, err := config.MigrateV8InMemoryCandidate(source, raw, guardrail.RulePackDigest)
	if err != nil {
		// Refused: the previous generation keeps running. As raw v8 the file
		// would drop its data.json admission and audit.db block/allow policy.
		return nil, config.InMemoryMigrationError(source, err)
	}
	candidate, err := config.LoadRuntimeV8CandidateFromBytes(source, migrated)
	if err != nil {
		return nil, err
	}
	candidate.RuntimeV8RulePackRebase = legacyV8 && !candidate.SecureClientIntegration()
	bindCandidateKeyExport(candidate, exportKey)
	return candidate, nil
}

// candidateKeyExports holds, for a candidate loaded from a config_version 8
// file, the export of the inline scanner key its in-memory migration moved
// to a variable (config.MigrateV8InMemoryCandidate). A reload runs it only
// when it activates the candidate, so a rejected candidate never changes
// the key the running scanners read. Keys are weak: an entry goes with its
// configuration.
var candidateKeyExports sync.Map // weak.Pointer[config.Config] -> func()

func bindCandidateKeyExport(cfg *config.Config, export func()) {
	if cfg == nil || export == nil {
		return
	}
	key := weak.Make(cfg)
	if _, loaded := candidateKeyExports.Swap(key, export); !loaded {
		runtime.AddCleanup(cfg, func(key weak.Pointer[config.Config]) { candidateKeyExports.Delete(key) }, key)
	}
}

// takeCandidateKeyExport removes and returns what bindCandidateKeyExport
// recorded for cfg; a no-op when there is none.
func takeCandidateKeyExport(cfg *config.Config) func() {
	if cfg != nil {
		if export, ok := candidateKeyExports.LoadAndDelete(weak.Make(cfg)); ok {
			return export.(func())
		}
	}
	return func() {}
}

func newConfigManagerWithSnapshot(
	path string,
	initial *config.Config,
	logger *audit.Logger,
	health *SidecarHealth,
	initialV8PlanDigest string,
	apply configSnapshotApplyFunc,
) *ConfigManager {
	if strings.TrimSpace(path) == "" {
		path = config.ConfigPath()
	}
	m := &ConfigManager{
		path:          filepath.Clean(path),
		applySnapshot: apply,
		logger:        logger,
		health:        health,
		loadSnapshot:  loadRuntimeConfigCandidate,
		readSnapshot:  readConfigFileSnapshot,
	}
	if initial != nil {
		m.current.Store(cloneConfig(initial))
	}
	if initial != nil && config.CurrentSchemaVersion(initial.ConfigVersion) {
		m.v8PlanDigest = strings.TrimSpace(initialV8PlanDigest)
	}
	return m
}

// SetEnvConfigPath wires the AVC env_config.json path onto an existing
// ConfigManager. Callers (managed_enterprise sidecar boot) invoke this
// after NewConfigManager and BEFORE Run — the fsnotify watch on the
// env_config parent dir is set up inside Run. A subsequent call to
// SetEnvConfigPath after Run has started has no effect on the watch
// set; Reload still picks up whatever the current value is.
func (m *ConfigManager) SetEnvConfigPath(path string) {
	if m == nil {
		return
	}
	trimmed := strings.TrimSpace(path)
	m.envConfigPath.Store(&trimmed)
}

func (m *ConfigManager) Current() *config.Config {
	if m == nil {
		return nil
	}
	v := m.current.Load()
	if cfg, ok := v.(*config.Config); ok {
		return cloneConfig(cfg)
	}
	return nil
}

// runWithStartupReconcile installs the watcher first, reconciles the currently
// active snapshot while filesystem events are already buffered, and reports
// readiness only after a quiet event window. Sidecar uses this as its serving
// gate so no configuration change can be missed between bootstrap and watch.
func (m *ConfigManager) runWithStartupReconcile(ctx context.Context, ready chan<- error) error {
	return m.run(ctx, ready)
}

// A watcher error is not necessarily a config read error. On macOS kqueue
// watches directory entries and can report EACCES for a private sibling of
// config.yaml. Reconcile the source and assets; only an actual reload failure
// should put config health in error.
func (m *ConfigManager) reconcileWatchError(ctx context.Context, watchErr error) {
	if err := m.ReloadAssets(ctx, "watch_error"); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "[config] watcher error (%v); reconciliation failed: %v\n", watchErr, err)
	}
}

func (m *ConfigManager) run(ctx context.Context, startupReady chan<- error) error {
	if m == nil {
		if startupReady != nil {
			startupReady <- nil
			close(startupReady)
		}
		return nil
	}
	if m.health != nil {
		m.setConfigHealth(StateRunning, "", map[string]interface{}{
			"path":       m.path,
			"generation": m.gen.Load(),
		})
	}
	if reporter := newBundleReceiptReporter(m.Current(), m.path, m.logger); reporter != nil {
		go reporter.run(ctx)
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		signalConfigStartupReady(startupReady, err)
		if m.health != nil {
			m.setConfigHealth(StateError, err.Error(), map[string]interface{}{"path": m.path})
		}
		return fmt.Errorf("config watcher: %w", err)
	}
	defer fsw.Close()

	dir := filepath.Dir(m.path)
	if err := fsw.Add(dir); err != nil {
		signalConfigStartupReady(startupReady, err)
		if m.health != nil {
			m.setConfigHealth(StateError, err.Error(), map[string]interface{}{"path": m.path})
		}
		return fmt.Errorf("config watcher: watch %s: %w", dir, err)
	}
	if m.afterWatchAdded != nil {
		m.afterWatchAdded()
	}
	// watchedAssets is the asset directory set currently registered with
	// fsw; syncAssetWatches reconciles it after every reload and on the
	// 30 s tick.
	watchedAssets := &assetWatches{fsw: fsw, watched: map[string]struct{}{}, failed: map[string]string{}}
	// assetDirSet holds the directories whose policy files are assets and
	// assetFileSet the single asset files, whose directories are watched too.
	assetDirSet, assetFileSet := map[string]struct{}{}, map[string]struct{}{}
	syncAssetWatches := func() bool {
		if m.assetDirs == nil && m.assetFiles == nil {
			return false
		}
		want := map[string]struct{}{}
		dirs, files := map[string]struct{}{}, map[string]struct{}{}
		var assetDirs, assetFiles []string
		if m.assetDirs != nil {
			assetDirs = m.assetDirs()
		}
		if m.assetFiles != nil {
			assetFiles = m.assetFiles()
		}
		if rejected := m.rejectedAssets.Load(); rejected != nil {
			assetDirs = append(slices.Clone(assetDirs), rejected.dirs...)
			assetFiles = append(slices.Clone(assetFiles), rejected.files...)
		}
		for _, assetDir := range assetDirs {
			assetDir = filepath.Clean(assetDir)
			dirs[assetDir] = struct{}{}
			if assetDir != dir {
				want[assetDir] = struct{}{}
			}
		}
		for _, assetFile := range assetFiles {
			assetFile = filepath.Clean(assetFile)
			files[assetFile] = struct{}{}
			if parent := filepath.Dir(assetFile); parent != dir {
				want[parent] = struct{}{}
			}
		}
		assetDirSet, assetFileSet = dirs, files
		added := watchedAssets.sync(want)
		m.setAssetWatchFailures(watchedAssets.failedPaths())
		return added
	}
	isAsset := func(path string) bool {
		cleaned := filepath.Clean(path)
		if _, ok := assetFileSet[cleaned]; ok {
			return true
		}
		if _, ok := assetDirSet[filepath.Dir(cleaned)]; !ok {
			if _, ok := assetDirSet[cleaned]; !ok {
				return false
			}
		}
		switch strings.ToLower(filepath.Ext(cleaned)) {
		case ".yaml", ".yml", ".rego", ".json", "":
			return true
		default:
			return false
		}
	}
	// Attach asset watches before reconciliation. Its first pass rebuilds
	// referenced assets, including edits made between boot and watch setup.
	syncAssetWatches()
	if startupReady != nil {
		if err := m.reconcileStartup(ctx, fsw, startupAssetWatches{syncAssetWatches, isAsset}); err != nil {
			signalConfigStartupReady(startupReady, err)
			return err
		}
		signalConfigStartupReady(startupReady, nil)
	}

	// Best-effort watch on the AVC env_config.json parent directory.
	// The dir may not exist yet (AVC packaging can drop it AFTER
	// DefenseClaw is installed) and it may equal the config.yaml dir
	// on unusual layouts. Deduping by string is enough — fsnotify
	// coalesces duplicate Add calls to a no-op anyway. We do NOT
	// treat a failure here as fatal: the config.yaml watch is the
	// primary channel; env_config-driven reloads are a nice-to-have.
	//
	// envConfigWatchedDir records the specific directory we succeeded
	// in registering — NOT just a bool. SetEnvConfigPath can be called
	// after Run has started (its doc contract) and can point at a
	// different directory than the one we first watched; a bare "were
	// we ever able to watch anything?" flag would then skip re-adding
	// the new directory, silently muting env_config-driven reloads for
	// the rest of the process lifetime. Empty means "no watch yet";
	// non-empty is the exact directory currently registered with fsw.
	var envConfigWatchedDir string
	// envConfigWatchedAncestor is the currently-watched *ancestor* of
	// the target env_config directory when the target itself doesn't
	// exist yet. Unclassified fsnotify events under this ancestor
	// (typically a Create when the target dir gets mkdir'd) re-arm
	// ensureEnvConfigWatched so the eventual creation of the target
	// dir promotes the watch immediately — without this the ancestor
	// watch would fire events that classify() drops, and only the 30s
	// ticker would notice.
	var envConfigWatchedAncestor string
	ensureEnvConfigWatched := func() {
		envPath := m.getEnvConfigPath()
		if envPath == "" {
			return
		}
		want := filepath.Dir(filepath.Clean(envPath))
		if want == dir {
			// Same directory as config.yaml — that watch is enough.
			envConfigWatchedDir = want
			envConfigWatchedAncestor = ""
			return
		}
		if envConfigWatchedDir == want {
			return
		}
		if err := fsw.Add(want); err == nil {
			envConfigWatchedDir = want
			envConfigWatchedAncestor = ""
			return
		}
		// Add failed — most likely because the directory doesn't
		// exist yet. Try the nearest existing ancestor so a
		// subsequent mkdir of the env_config dir surfaces as a
		// fsnotify Create event under the ancestor — the event-loop's
		// "unclassified event under envConfigWatchedAncestor" branch
		// (below) then re-arms this function, which finally succeeds
		// in adding the target dir now that it exists.
		for anc := filepath.Dir(want); anc != "" && anc != "/" && anc != filepath.Dir(anc); anc = filepath.Dir(anc) {
			if err := fsw.Add(anc); err == nil {
				envConfigWatchedAncestor = anc
				return
			}
		}
	}
	// First-boot attempt. On failure the ticker + per-reload retry
	// below will keep re-trying, and SetEnvConfigPath is also safe to
	// call after Run has started.
	ensureEnvConfigWatched()

	// Independent retry ticker. Without this, the env_config watch
	// only re-tries when SOME OTHER watched file (config.yaml) fires
	// a reload event — but env_config is meant to be the trigger
	// itself. If the AVC pipeline drops env_config.json at
	// /opt/cisco/secureclient/defenseclaw/env_config.json 3 hours
	// after install and config.yaml hasn't changed in the meantime,
	// nothing would ever notice without a periodic probe.
	envWatchRetryTicker := time.NewTicker(30 * time.Second)
	defer envWatchRetryTicker.Stop()
	retryInterval := m.permissionRetryInterval
	if retryInterval <= 0 {
		retryInterval = configReloadPermissionRetry
	}
	permissionRetryTicker := time.NewTicker(retryInterval)
	defer permissionRetryTicker.Stop()

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	pending := false
	// pendingTrigger identifies which of the two watched files
	// armed the debounce, so the reason= tag on the reload log line
	// tells operators which file changed. First event of a burst
	// wins (subsequent events in the same debounce window are
	// already scheduled and don't need to be re-labelled).
	pendingTrigger := ""
	// pendingKinds records every kind of file in the burst: an asset forces
	// a generation rebuild even without a config diff, and a burst of only
	// config.generation.json refreshes config_generation.
	pendingKinds := map[string]bool{}
	// A burst seen and not applied yet holds the profile oracle back
	// (configReloadInFlight).
	defer func() {
		if pending {
			configReloadInFlight.settle()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			if m.health != nil {
				m.setConfigHealth(StateStopped, "", map[string]interface{}{"path": m.path})
			}
			return ctx.Err()
		case event := <-fsw.Events:
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				watchedAssets.removed(event.Name)
			}
			which := m.classify(event.Name)
			if which == "" && isAsset(event.Name) {
				which = configDiffAssets
			}
			if which == "" {
				// Unclassified event, but it might be a Create under
				// our ancestor watch — the "AVC just mkdir'd the
				// env_config parent directory" case that lets the
				// watch we deferred at boot actually attach. If we
				// have an ancestor watch and this Create looks like
				// it's under it, re-run ensureEnvConfigWatched so the
				// target-dir Add can succeed now.
				if envConfigWatchedAncestor != "" &&
					event.Op&fsnotify.Create != 0 &&
					filepath.Dir(filepath.Clean(event.Name)) == envConfigWatchedAncestor {
					ensureEnvConfigWatched()
				}
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			if which != configDiffAssets && event.Op&fsnotify.Remove != 0 {
				continue
			}
			if !pending {
				pendingTrigger = which
				configReloadInFlight.begin()
			}
			pendingKinds[which] = true
			pending = true
			resetTimer(timer, configReloadDebounce)
		case err := <-fsw.Errors:
			if err != nil {
				// kqueue can report a permission error for another entry in
				// the watched directory (for example a private bundle inbox).
				// Check the config and its assets before changing config health.
				m.reconcileWatchError(ctx, err)
				syncAssetWatches()
			}
		case <-timer.C:
			if !pending {
				continue
			}
			reason := "fsnotify"
			if pendingTrigger != "" {
				reason = "fsnotify:" + pendingTrigger
			}
			kinds := pendingKinds
			pending = false
			pendingTrigger = ""
			pendingKinds = map[string]bool{}
			if len(kinds) == 1 && kinds[configGenerationTrigger] {
				// A bundle can replace policy assets without changing parsed
				// config fields. Its generation record is then the only event
				// that tells us to build and audit the new policy.
				m.mu.Lock()
				pendingBundle := m.pendingBundleGeneration(nil)
				m.mu.Unlock()
				if pendingBundle {
					if err := m.reload(ctx, reason, false); err != nil && ctx.Err() == nil {
						fmt.Fprintf(os.Stderr, "[config] reload failed: %v\n", err)
					}
				} else {
					refreshConfigGeneration(nil)
				}
				configReloadInFlight.settle()
				continue
			}
			// A reload the gateway's own stop or restart cancelled is not a
			// failure; the restart applies the new config (GAP-1698).
			if err := m.reload(ctx, reason, kinds[configDiffAssets]); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[config] reload failed: %v\n", err)
			}
			configReloadInFlight.settle()
			syncAssetWatches()
			// Piggyback on the reload path — the AVC packaging pipeline
			// may have just created the env_config directory. The
			// independent envWatchRetryTicker below covers the case
			// where NOTHING in config.yaml has changed but env_config
			// arrives on its own timeline.
			ensureEnvConfigWatched()
		case <-envWatchRetryTicker.C:
			ensureEnvConfigWatched()
			// An asset folder that was deleted and created again (or
			// created after the generation named it) is watched again
			// here; rebuild the generation from it. A folder that cannot
			// be watched is polled instead (GAP-0879).
			if syncAssetWatches() || watchedAssets.failedFoldersChanged() {
				if !pending {
					pendingTrigger = configDiffAssets
					configReloadInFlight.begin()
				}
				pendingKinds[configDiffAssets] = true
				pending = true
				resetTimer(timer, configReloadDebounce)
			}
		case <-permissionRetryTicker.C:
			m.mu.Lock()
			retry := m.permissionRetry
			m.mu.Unlock()
			if retry && !pending {
				if err := m.Reload(ctx, "permission_retry"); err != nil && ctx.Err() == nil {
					fmt.Fprintf(os.Stderr, "[config] reload retry failed: %v\n", err)
				}
				syncAssetWatches()
			}
		}
	}
}

// assetWatches is the set of asset directories registered with the config
// watcher.
type assetWatches struct {
	fsw     *fsnotify.Watcher
	watched map[string]struct{}
	// failed holds each wanted folder the watcher could not watch, with the
	// fingerprint of its entries (assetFolderFingerprint) when it failed.
	failed map[string]string
}

// failedPaths lists the folders the watcher could not watch, sorted.
func (a *assetWatches) failedPaths() []string {
	if len(a.failed) == 0 {
		return nil
	}
	paths := make([]string, 0, len(a.failed))
	for path := range a.failed {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// failedFoldersChanged reports whether a folder the watcher could not watch
// changed since it was last checked, the polling fallback for a watch that
// keeps failing (inotify limits, permissions).
func (a *assetWatches) failedFoldersChanged() bool {
	changed := false
	for path, before := range a.failed {
		if now := assetFolderFingerprint(path); now != before {
			a.failed[path] = now
			changed = true
		}
	}
	return changed
}

// maxAssetFingerprintFileBytes bounds how much of one file the polling
// fingerprint reads.
const maxAssetFingerprintFileBytes = 8 << 20

// assetFolderFingerprint digests the names, sizes, modes and modification
// times of a folder's entries and the contents of its files, so an edit
// that keeps a file's size and modification time changes it too ("" when
// the folder cannot be read).
func assetFolderFingerprint(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	sum := sha256.New()
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			fmt.Fprintf(sum, "%s\x00?\x00", entry.Name())
			continue
		}
		fmt.Fprintf(sum, "%s\x00%d\x00%d\x00%d\x00", entry.Name(), info.Size(), info.Mode(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			hashAssetFileContents(sum, filepath.Join(dir, entry.Name()))
		}
	}
	return fmt.Sprintf("%x", sum.Sum(nil))
}

// hashAssetFileContents writes the first maxAssetFingerprintFileBytes of
// the file at path to sum, or a marker when it cannot be read.
func hashAssetFileContents(sum io.Writer, path string) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprint(sum, "?\x00")
		return
	}
	defer file.Close()
	if _, err := io.Copy(sum, io.LimitReader(file, maxAssetFingerprintFileBytes)); err != nil {
		fmt.Fprint(sum, "?\x00")
	}
}

// sync watches exactly want. A watched folder that is gone lost its watch
// with it, so it is dropped and watched again once it is back (GAP-0266). It
// reports whether it started watching a folder.
func (a *assetWatches) sync(want map[string]struct{}) (added bool) {
	for assetDir := range a.watched {
		_, keep := want[assetDir]
		if keep {
			if _, err := os.Stat(assetDir); err == nil {
				continue
			}
		}
		_ = a.fsw.Remove(assetDir)
		delete(a.watched, assetDir)
	}
	for assetDir := range a.failed {
		if _, keep := want[assetDir]; !keep {
			delete(a.failed, assetDir)
		}
	}
	for assetDir := range want {
		if _, done := a.watched[assetDir]; done {
			continue
		}
		if err := a.fsw.Add(assetDir); err == nil {
			a.watched[assetDir] = struct{}{}
			delete(a.failed, assetDir)
			added = true
		} else if _, statErr := os.Stat(assetDir); statErr != nil {
			// A folder that is not there yet is watched once it is.
			delete(a.failed, assetDir)
		} else if _, known := a.failed[assetDir]; !known && a.failed != nil {
			a.failed[assetDir] = assetFolderFingerprint(assetDir)
		}
	}
	return added
}

// removed forgets a watched folder a Remove or Rename event names: its watch
// died with it, so the next sync adds it again when it is back.
func (a *assetWatches) removed(path string) {
	path = filepath.Clean(path)
	if _, ok := a.watched[path]; ok {
		_ = a.fsw.Remove(path)
		delete(a.watched, path)
	}
}

type startupAssetWatches struct {
	sync    func() bool
	isAsset func(string) bool
}

func (m *ConfigManager) reconcileStartup(ctx context.Context, fsw *fsnotify.Watcher, watches ...startupAssetWatches) error {
	if m == nil || fsw == nil {
		return fmt.Errorf("config startup reconciliation is unavailable")
	}
	var assets startupAssetWatches
	if len(watches) > 0 {
		assets = watches[0]
	}
	hasAssets := m.assetDirs != nil || m.assetFiles != nil
	for first := true; ; first = false {
		if hasAssets {
			if err := m.ReloadAssets(ctx, "startup_reconcile"); err != nil {
				return err
			}
		} else if !first || !m.startupSourceUnchanged(ctx) {
			if err := m.Reload(ctx, "startup_reconcile"); err != nil {
				return err
			}
		}
		if assets.sync != nil {
			assets.sync()
		}
		timer := time.NewTimer(configReloadStartupQuietPeriod)
		dirty := false
		for {
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return ctx.Err()
			case event := <-fsw.Events:
				assetEvent := assets.isAsset != nil && assets.isAsset(event.Name)
				if (m.matches(event.Name) || assetEvent) &&
					event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
					dirty = true
				}
			case watchErr := <-fsw.Errors:
				if watchErr != nil {
					m.reconcileWatchError(ctx, watchErr)
					if assets.sync != nil {
						assets.sync()
					}
				}
			case <-timer.C:
				if dirty {
					break
				}
				return nil
			}
			if dirty {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				break
			}
		}
	}
}

// setStartupSource records the bytes the gateway booted from, read from
// sourceName; a source other than the watched file is not recorded.
func (m *ConfigManager) setStartupSource(sourceName string, raw []byte) {
	if m == nil || len(raw) == 0 || filepath.Clean(strings.TrimSpace(sourceName)) != m.path {
		return
	}
	m.startupSource, m.startupKnown = sha256.Sum256(raw), true
	// The boot bytes hold every generation recorded so far (and a hand edit
	// made on top while the gateway was stopped); no state file yet means
	// none was written.
	state, err := configwrite.ReadGenerationState(m.path)
	switch {
	case err == nil:
		m.appliedGeneration, m.appliedGenerationKnown = state.Generation, true
	case errors.Is(err, fs.ErrNotExist):
		m.appliedGeneration, m.appliedGenerationKnown = 0, true
	}
}

// noteAppliedGeneration records the generation of the applied raw bytes;
// bytes no writer recorded (a hand edit) leave it unchanged. Callers hold mu.
func (m *ConfigManager) noteAppliedGeneration(raw []byte) {
	if generation, ok := appliedGenerationOf(m.path, raw); ok {
		m.appliedGeneration, m.appliedGenerationKnown = generation, true
	}
}

// savedWriteNotApplied reports whether raw holds a saved write the gateway
// has not applied: bytes other than the applied ones, or a recorded
// generation newer than the applied one. Without applied bytes only a newer
// generation counts, so unchanged bytes never repeat the last writer's
// config.change.applied. Callers hold mu.
func (m *ConfigManager) savedWriteNotApplied(raw []byte) bool {
	if m.appliedRaw != nil && !bytes.Equal(m.appliedRaw, raw) {
		return true
	}
	generation, ok := appliedGenerationOf(m.path, raw)
	return ok && m.appliedGenerationKnown && generation > m.appliedGeneration
}

// pendingBundleGeneration is true only for a new lifecycle-recorded bundle
// whose generation has not passed through the config manager's apply path.
func (m *ConfigManager) pendingBundleGeneration(raw []byte) bool {
	state, err := configwrite.ReadGenerationState(m.path)
	return err == nil && state.BundleID != "" && m.appliedGenerationKnown &&
		state.Generation > m.appliedGeneration &&
		(raw == nil || strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), configwrite.SHA256Hex(raw)))
}

// startupSourceUnchanged reports whether config.yaml still holds the bytes
// the gateway booted from, so the startup reconcile has nothing to apply.
// Its reload parsed, validated and compiled the whole file a second time on
// the start path, which a large guardrail policy made the slowest part of a
// start (GAP-0264). It still does what that reload does for unchanged bytes:
// record a hand edit made while the gateway was stopped, publish the
// config_generation and keep the bytes the next change is compared with. The
// Secure Client env_config overlay is applied by that reload, so a gateway
// with one always reloads.
func (m *ConfigManager) startupSourceUnchanged(ctx context.Context) bool {
	if m == nil || !m.startupKnown || m.readSnapshot == nil || m.getEnvConfigPath() != "" || ManagedEnterpriseActive() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot, err := m.readSnapshot(m.path)
	if err != nil || sha256.Sum256(snapshot.raw) != m.startupSource {
		return false
	}
	recordHandEdit(ctx, m.Current(), m.path, snapshot.raw)
	refreshConfigGeneration(snapshot.raw)
	m.appliedRaw = snapshot.raw
	m.noteAppliedGeneration(snapshot.raw)
	version.SetContentHash(snapshot.raw)
	if m.health != nil {
		m.setConfigHealth(StateRunning, "", map[string]interface{}{
			"path": m.path, "generation": m.gen.Load(), "reason": "startup_reconcile", "changed": []string{},
		})
	}
	return true
}

func signalConfigStartupReady(ready chan<- error, err error) {
	if ready == nil {
		return
	}
	ready <- err
	close(ready)
}

func (m *ConfigManager) Reload(ctx context.Context, reason string) error {
	return m.reload(ctx, reason, false)
}

// ReloadAssets is Reload that rebuilds the generation even when config.yaml
// is unchanged, because a referenced asset may have changed
// (/policy/reload).
func (m *ConfigManager) ReloadAssets(ctx context.Context, reason string) error {
	return m.reload(ctx, reason, true)
}

func (m *ConfigManager) reload(ctx context.Context, reason string, assets bool) error {
	if m == nil {
		return nil
	}
	started := time.Now()
	var applyElapsed, auditElapsed time.Duration
	hot := true
	defer func() {
		if hot && time.Since(started) > time.Second {
			fmt.Fprintf(os.Stderr, "[config] slow hot reload elapsed_ms=%d apply_ms=%d audit_ms=%d\n",
				time.Since(started).Milliseconds(), applyElapsed.Milliseconds(), auditElapsed.Milliseconds())
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()

	oldCfg := m.Current()
	next, source, err := m.loadStableCandidate(ctx)
	// The candidate's inline scanner key applies only once it is accepted.
	exportCandidateKey := takeCandidateKeyExport(next)
	if err != nil {
		m.rejected = true
		m.permissionRetry = errors.Is(err, os.ErrPermission)
		recordGenerationBuildError(err)
		m.recordLoadError(ctx, "candidate_invalid")
		if m.health != nil {
			m.setConfigHealth(StateError, err.Error(), map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
			})
		}
		return err
	}
	m.permissionRetry = false
	if oldCfg == nil || !config.CurrentSchemaVersion(oldCfg.ConfigVersion) ||
		!config.CurrentSchemaVersion(next.ConfigVersion) {
		m.recordLoadError(ctx, "schema_version")
		return fmt.Errorf("config reload: the configuration is from an older DefenseClaw; run 'defenseclaw migrate' first")
	}
	if oldCfg != nil && managed.IsManagedEnterprise(oldCfg.DeploymentMode) && !managed.IsManagedEnterprise(next.DeploymentMode) {
		m.recordLoadError(ctx, "managed_downgrade")
		return fmt.Errorf("config reload cannot downgrade deployment_mode from managed_enterprise")
	}
	// Only a change between two managed profiles is a reinstall. An unmanaged
	// config has no profile, so switching it to managed_enterprise keeps its
	// pre-profile behavior: deployment_mode is restart-required below.
	if oldCfg != nil && managed.IsManagedEnterprise(oldCfg.DeploymentMode) &&
		managed.IsManagedEnterprise(next.DeploymentMode) &&
		oldCfg.EnterpriseProfile() != next.EnterpriseProfile() {
		m.recordLoadError(ctx, "enterprise_profile_change")
		return fmt.Errorf("config reload cannot change the enterprise profile from %q to %q; reinstall through the lifecycle", oldCfg.EnterpriseProfile(), next.EnterpriseProfile())
	}
	// AVC env_config.json overlay. When present and well-formed the
	// endpoint from env_config wins over whatever the installer wrote
	// into config.yaml, so a region change delivered AFTER install
	// takes effect on the next reload. When the file is missing (the
	// pre-arrival case) we leave next.CiscoAIDefense.Endpoint alone,
	// which yields the config.yaml value (a hardcoded US-prod default
	// during install if env_config was also missing at install time).
	// When the file is present but malformed we LOG + RETAIN — we
	// refuse to blow away a working endpoint with a bad one because a
	// hostile env_config is precisely the exfiltration vector the
	// validate step defends against.
	var envOverlayErr error
	if envPath := m.getEnvConfigPath(); envPath != "" {
		ep, envErr := config.LoadEnvConfigEndpoint(envPath)
		switch {
		case envErr == nil:
			// The strings.TrimRight("/", ...) call inside
			// NewCiscoDefenseClawInspectClient tolerates a trailing
			// slash; we don't normalise here so the diff engine can
			// see exactly what's on disk.
			next.CiscoAIDefense.Endpoint = ep
			m.envOverlayApplied.Store(true)
		case errors.Is(envErr, config.ErrEnvConfigMissing) && m.envOverlayApplied.Load():
			// File disappeared AFTER we had already applied an overlay
			// endpoint. Treat this the same as a malformed overlay: a
			// legitimate AVC region change comes via a rewritten file,
			// not a deletion, and silently reverting to the config.yaml
			// default would ship a data-residency violation with zero
			// operator signal.
			if oldCfg != nil {
				next.CiscoAIDefense.Endpoint = oldCfg.CiscoAIDefense.Endpoint
			}
			fmt.Fprintf(os.Stderr, "[config] env_config overlay disappeared after prior successful apply: retaining current endpoint\n")
			envOverlayErr = fmt.Errorf("env_config overlay disappeared after prior successful apply: %w", envErr)
		case errors.Is(envErr, config.ErrEnvConfigMissing):
			// Pre-arrival: env_config.json has never been present.
			// Leave next.CiscoAIDefense.Endpoint alone, which yields
			// the config.yaml value (a hardcoded US-prod default when
			// env_config was also missing at install time).
		default:
			// Malformed / rejected env_config. Copy the currently-active
			// endpoint (oldCfg) onto next so a bad overlay cannot revert
			// the runtime endpoint to the config.yaml value. `next` was
			// just loaded from config.yaml and doesn't yet reflect the
			// last-good env_config overlay we applied; leaving it alone
			// would drop that overlay on the next diff.
			//
			// Surface a health-check error so the operator sees it in
			// the sidecar status output but keep serving traffic against
			// the current endpoint. The health write is deferred to the
			// terminal SetConfig calls below so the successful-apply /
			// no-diff paths don't unconditionally overwrite the error
			// state.
			if oldCfg != nil {
				next.CiscoAIDefense.Endpoint = oldCfg.CiscoAIDefense.Endpoint
			}
			fmt.Fprintf(os.Stderr, "[config] env_config overlay rejected: %v (retaining current endpoint)\n", envErr)
			envOverlayErr = envErr
		}
	}
	// managed_enterprise: carry boot-time-derived runtime Gateway
	// fields forward onto the freshly-loaded snapshot BEFORE we diff.
	// Extracted into preserveManagedGatewayRuntimeFields so tests can
	// exercise the exact production preservation path via Reload
	// (rather than duplicating the logic locally, which would let a
	// regression here slip past the test suite).
	preserveManagedGatewayRuntimeFields(oldCfg, next)
	// Inject the release-owned managed destination NOW, after the
	// env_config overlay above has resolved next.CiscoAIDefense.Endpoint
	// and preserveManagedGatewayRuntimeFields has settled any oldCfg
	// carry-forward. Both sides of the subsequent digest / equivalence
	// comparison then see the same endpoint that Sidecar's apply
	// boundary will recompute with. Doing this before the overlay bakes
	// the raw config.yaml endpoint into compiled.Plan, which then fails
	// idempotency at the Sidecar boundary with "generated
	// managed-enterprise destination rejected".
	if source.compiledV8 != nil && source.compiledV8.Plan != nil {
		if err := applySidecarObservabilityV8ManagedDestination(
			source.compiledV8,
			sidecarObservabilityV8ManagedOptionsFromConfig(next, source.raw),
		); err != nil {
			m.recordLoadError(ctx, "managed_destination_rejected")
			if m.health != nil {
				m.setConfigHealth(StateError, err.Error(), map[string]interface{}{
					"path":       m.path,
					"generation": m.gen.Load(),
					"reason":     reason,
				})
			}
			return fmt.Errorf(
				"config reload observability v8 managed destination: %w", err,
			)
		}
	}
	diff := diffConfigs(oldCfg, next)
	// In hot mode a restart-required edit (a listener, the hook settings
	// setup bakes in, the resource identity, a section still read once at
	// start) keeps its running value and is reported as pending, so the rest
	// of the edit, and every later one, still applies instead of each reload
	// failing until the gateway restarts. A storage path or deployment_mode
	// change can not be held (holdRestartRequired) and still fails the
	// reload. Secure Client keeps its behaviour.
	var pendingRestart []string
	if len(diff.RestartRequired) > 0 && configReloadMode(next) != "restart" &&
		!oldCfg.SecureClientIntegration() && !next.SecureClientIntegration() {
		if held := holdRestartRequired(oldCfg, next, diff.RestartRequired); held != nil {
			if heldDiff := diffConfigs(oldCfg, held); len(heldDiff.RestartRequired) == 0 {
				pendingRestart = diff.RestartRequired
				next, diff = held, heldDiff
			}
		}
	}
	hot = len(diff.RestartRequired) == 0
	if source.compiledV8 != nil && source.compiledV8.Plan != nil && m.observabilityV8PlanChanged(source.compiledV8.Plan) {
		diff.Changed = sortedUniqueStrings(append(diff.Changed, "observability"))
	}
	// On a standalone managed host the lifecycle's signed bundle is the only
	// source of a new config or policy generation. A watcher event or an
	// authenticated API call cannot turn hand-edited bytes or assets active.
	// The boot bytes are already the running snapshot and may be reconciled
	// once before the manager has an applied generation.
	startupBoot := !assets && !m.rejected && reason == "startup_reconcile" && m.appliedRaw == nil && m.startupKnown &&
		sha256.Sum256(source.raw) == m.startupSource
	pendingBundle := m.pendingBundleGeneration(source.raw)
	// A watched asset can be checked without a new bundle only when the
	// config bytes are the ones already running. At startup those are the
	// exact boot bytes; later they are the last applied bytes. The same proof
	// repairs a standing rejection after the operator restores those bytes.
	// The sidecar rebuilds all referenced assets and refuses any difference.
	knownBytes := m.appliedRaw != nil && bytes.Equal(m.appliedRaw, source.raw) ||
		m.appliedRaw == nil && m.startupKnown && sha256.Sum256(source.raw) == m.startupSource
	proveUnchanged := !pendingBundle && knownBytes && (assets || m.rejected) &&
		oldCfg.StandaloneEnterprise() && next.StandaloneEnterprise()
	if (oldCfg.StandaloneEnterprise() || next.StandaloneEnterprise()) && !startupBoot &&
		!pendingBundle && !proveUnchanged &&
		(assets || m.rejected || !bytes.Equal(m.appliedRaw, source.raw) || len(diff.Changed) > 0) {
		err := fmt.Errorf("config reload refused: this managed computer takes config and policy from a signed policy bundle; apply a new signed bundle")
		m.rejected = true
		recordGenerationBuildError(err)
		m.recordLoadError(ctx, "managed_unbundled_reload")
		if m.health != nil {
			m.setConfigHealth(StateError, err.Error(), map[string]interface{}{
				"path": m.path, "generation": m.gen.Load(), "reason": reason,
			})
		}
		return err
	}
	if !proveUnchanged {
		setPendingRestart(pendingRestart)
		if len(pendingRestart) > 0 {
			fmt.Fprintf(os.Stderr, "[config] restart the gateway to apply %s; the rest of the change applies now\n",
				strings.Join(pendingRestart, ", "))
		}
	}
	// A standing rejection also forces a rebuild: the repair (an asset
	// restored, a bad config edit reverted) changes nothing the diff sees,
	// and without the rebuild the error would stay until some unrelated
	// change.
	if len(diff.Changed) == 0 && (assets || m.rejected) {
		diff.Changed = []string{configDiffAssets}
	}
	if len(diff.Changed) == 0 && pendingBundle {
		// The bundle may have changed only a referenced policy file. Build
		// its generation before recording that it was applied.
		diff.Changed = []string{configDiffAssets}
	}
	if len(diff.Changed) == 0 {
		exportCandidateKey()
		recordHandEdit(ctx, next, m.path, source.raw)
		refreshConfigGeneration(source.raw)
		// Saved intent can change without changing the running settings:
		// holding a listener until restart, cancelling that pending change,
		// or removing an explicit default. Attribute each saved write before
		// advancing the source/generation watermark.
		if m.logger != nil && !next.SecureClientIntegration() && m.savedWriteNotApplied(source.raw) {
			if activity, _, recorded := configChangeActivity(m.path, m.appliedRaw, source.raw,
				pendingRestart, pendingRestart, m.appliedGeneration, m.appliedGenerationKnown); recorded {
				_ = m.logger.LogActivity(activity)
			}
		}
		// A bundle can advance its persistent generation while keeping
		// config.yaml identical. An asset reload must still be able to
		// attribute the later policy swap to that bundle.
		if state, err := configwrite.ReadGenerationState(m.path); err != nil ||
			state.BundleID == "" || !m.appliedGenerationKnown ||
			state.Generation <= m.appliedGeneration || !bytes.Equal(m.appliedRaw, source.raw) {
			m.noteAppliedGeneration(source.raw)
		}
		m.appliedRaw = source.raw
		if source.compiledV8 != nil && source.compiledV8.Plan != nil {
			m.v8PlanDigest = source.compiledV8.Plan.Digest()
			m.v8Plan = source.compiledV8.Plan
		}
		version.SetContentHash(source.raw)
		if m.health != nil {
			state := StateRunning
			msg := ""
			if envOverlayErr != nil {
				state = StateError
				msg = envOverlayErr.Error()
			}
			detail := map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
				"changed":    []string{},
			}
			if len(pendingRestart) > 0 {
				detail["restart_required"] = pendingRestart
			}
			m.setConfigHealth(state, msg, detail)
		}
		return nil
	}
	if m.applySnapshot == nil {
		m.recordLoadError(ctx, "apply_unavailable")
		return fmt.Errorf("config reload schema v8 requires a source-aware apply callback")
	}
	source.proveUnchanged = proveUnchanged
	applyStarted := time.Now()
	applyErr := m.applySnapshot(ctx, oldCfg, next, diff, cloneConfigReloadSource(source))
	applyElapsed = time.Since(applyStarted)
	if proveUnchanged && applyErr == nil {
		applyErr = fmt.Errorf("config reload refused: managed generation was not proven unchanged; apply a new signed policy bundle")
	}
	if errors.Is(applyErr, errGenerationUnchanged) {
		// The rebuild succeeded and matches the live generation: nothing to
		// swap, but an earlier rejected edit is resolved (a pack restored
		// after a digest mismatch), so clear its last_reload_error and error
		// state; otherwise they stay until an unrelated config write.
		m.rejected = false
		m.rejectedAssets.Store(nil)
		clearGenerationBuildError()
		if !proveUnchanged || m.appliedRaw == nil {
			exportCandidateKey()
			recordHandEdit(ctx, next, m.path, source.raw)
			refreshConfigGeneration(source.raw)
			version.SetContentHash(source.raw)
		}
		// The startup reconcile of the boot bytes applies nothing new: they
		// become the applied bytes, so a later event for the same bytes
		// does not attribute their writer again.
		if m.appliedRaw == nil && m.startupKnown && sha256.Sum256(source.raw) == m.startupSource {
			m.appliedRaw = source.raw
		}
		if m.health != nil {
			state, msg := StateRunning, ""
			if envOverlayErr != nil {
				state, msg = StateError, envOverlayErr.Error()
			}
			m.setConfigHealth(state, msg, map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
				"changed":    []string{},
			})
		}
		return nil
	}
	if applyErr != nil {
		m.rejected = true
		m.noteRejectedCandidateAssets(next)
		m.permissionRetry = errors.Is(applyErr, os.ErrPermission)
		recordGenerationBuildError(applyErr)
		m.recordLoadError(ctx, "apply_rejected")
		if m.health != nil {
			m.setConfigHealth(StateError, applyErr.Error(), map[string]interface{}{
				"path":             m.path,
				"generation":       m.gen.Load(),
				"reason":           reason,
				"changed":          diff.Changed,
				"restart_required": diff.RestartRequired,
			})
		}
		return applyErr
	}
	m.rejected = false
	m.rejectedAssets.Store(nil)
	gen := m.gen.Add(1)
	m.current.Store(cloneConfig(next))
	exportCandidateKey()
	recordHandEdit(ctx, next, m.path, source.raw)
	if source.compiledV8 != nil && source.compiledV8.Plan != nil {
		m.v8PlanDigest = source.compiledV8.Plan.Digest()
		m.v8Plan = source.compiledV8.Plan
	}
	version.SetContentHash(source.raw)
	if next.StandaloneEnterprise() && !bytes.Equal(m.appliedRaw, source.raw) {
		awaitRecordedConfigBytes(ctx, m.path, source.raw)
	}
	activity, appliedGeneration, recorded := configChangeActivity(m.path, m.appliedRaw, source.raw, diff.Changed,
		append(append([]string{}, diff.RestartRequired...), pendingRestart...),
		m.appliedGeneration, m.appliedGenerationKnown)
	if recorded {
		m.appliedGeneration, m.appliedGenerationKnown = appliedGeneration, true
		if activity.Bundle != nil {
			activity.After["policy_generation_before"] = gen - 1
			activity.After["policy_generation_after"] = gen
		}
	}
	// A signed bundle may change policy assets while preserving config.yaml.
	// configChangeActivity only attributes that swap when its generation
	// record advanced; an ordinary asset rebuild cannot reuse the writer.
	if m.logger != nil && (next.SecureClientIntegration() || !bytes.Equal(m.appliedRaw, source.raw) || recorded) {
		auditStarted := time.Now()
		if recorded && !next.SecureClientIntegration() {
			_ = m.logger.LogActivity(activity)
		} else {
			_ = m.logger.LogActionCtx(ctx, string(audit.ActionConfigUpdate), m.path,
				fmt.Sprintf("generation=%d changed=%s reason=%s", gen, strings.Join(diff.Changed, ","), reason))
		}
		auditElapsed = time.Since(auditStarted)
	}
	m.appliedRaw = source.raw
	if m.health != nil {
		state := StateRunning
		msg := ""
		if envOverlayErr != nil {
			state = StateError
			msg = envOverlayErr.Error()
		}
		detail := map[string]interface{}{
			"path":             m.path,
			"generation":       gen,
			"reason":           reason,
			"changed":          diff.Changed,
			"restart_required": append(append([]string{}, diff.RestartRequired...), pendingRestart...),
			"last_success":     time.Now().UTC().Format(time.RFC3339),
		}
		m.setConfigHealth(state, msg, detail)
	}
	return nil
}

func (m *ConfigManager) observabilityV8PlanChanged(candidate *config.ObservabilityV8Plan) bool {
	if m == nil || candidate == nil {
		return false
	}
	if m.v8Plan != nil {
		return !candidate.ReloadEquivalent(m.v8Plan)
	}
	return candidate.Digest() != m.v8PlanDigest
}

func (m *ConfigManager) loadStableCandidate(ctx context.Context) (*config.Config, configReloadSource, error) {
	if m == nil || m.loadSnapshot == nil || m.readSnapshot == nil {
		return nil, configReloadSource{}, fmt.Errorf("config reload snapshot loader is unavailable")
	}
	for attempt := 1; attempt <= configReloadSnapshotAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, configReloadSource{}, err
		}
		before, beforeErr := m.readSnapshot(m.path)
		if beforeErr != nil {
			if isConfigSnapshotChanged(beforeErr) {
				continue
			}
			return nil, configReloadSource{}, beforeErr
		}
		defaultDataDir, secureClient := "", false
		if current := m.Current(); current != nil {
			defaultDataDir, secureClient = current.DataDir, current.SecureClientIntegration()
		}
		if defaultDataDir != "" && !secureClient {
			// A destination key added to .env after the gateway started (by
			// `setup galileo --persist-api-key` or `keys set`) must resolve
			// when the config that references it reloads (GAP-0017). Secure
			// Client reads .env only at start (issue #1092).
			config.LoadDotEnv(filepath.Join(defaultDataDir, ".env"))
		}
		compileRaw := before.raw
		var compileErr error
		if !secureClient && config.NeedsMigrationV9(compileRaw) {
			// The runtime loader migrates v8 read-only as well. Validate the
			// same candidate here, rather than rejecting its legacy keys before
			// that loader can run. Do not export candidate secrets before apply.
			compileRaw, _, compileErr = config.MigrateV8InMemoryCandidate(m.path, compileRaw, guardrail.RulePackDigest)
			if compileErr != nil {
				compileErr = config.InMemoryMigrationError(m.path, compileErr)
			}
		}
		var compiled *config.ObservabilityV8CompiledConfig
		if compileErr == nil {
			compiled, compileErr = config.ParseCompileObservabilityV8(m.path, compileRaw,
				config.ObservabilityV8CompileOptions{DefaultDataDir: defaultDataDir})
		}
		var next *config.Config
		var loadErr error
		if compileErr == nil {
			next, loadErr = m.loadSnapshot(m.path, before.raw)
		}
		after, afterErr := m.readSnapshot(m.path)
		if afterErr != nil {
			if isConfigSnapshotChanged(afterErr) {
				continue
			}
			return nil, configReloadSource{}, afterErr
		}
		if !sameConfigFileSnapshot(before, after) {
			continue
		}
		if compileErr != nil {
			return nil, configReloadSource{}, compileErr
		}
		if loadErr != nil {
			return nil, configReloadSource{}, loadErr
		}
		if next == nil {
			return nil, configReloadSource{}, fmt.Errorf("config reload loader returned no candidate")
		}
		source := configReloadSource{
			sourceName: m.path,
			raw:        append([]byte(nil), before.raw...),
		}
		if !config.CurrentSchemaVersion(next.ConfigVersion) {
			return nil, configReloadSource{}, fmt.Errorf("config reload: the configuration is from an older DefenseClaw; run 'defenseclaw migrate' first")
		}
		if compiled == nil || compiled.Plan == nil {
			return nil, configReloadSource{}, fmt.Errorf("config reload v8 compiler returned no effective plan")
		}
		snapshot := compiled.Plan.Snapshot()
		if strings.TrimSpace(snapshot.Local.Path) == "" || strings.TrimSpace(snapshot.Local.JudgeBodiesPath) == "" {
			return nil, configReloadSource{}, fmt.Errorf("config reload v8 local store paths are incomplete")
		}
		next.DataDir = compiled.DataDir
		if err := config.ApplyRuntimeV8DataDirDefaultsFromBytes(next, m.path, before.raw, compiled.DataDir); err != nil {
			return nil, configReloadSource{}, err
		}
		next.AuditDB = snapshot.Local.Path
		next.JudgeBodiesDB = snapshot.Local.JudgeBodiesPath
		// NOTE: the release-owned managed-enterprise destination is NOT
		// injected here. `next.CiscoAIDefense.Endpoint` at this point is
		// the raw config.yaml value; the AVC env_config.json overlay
		// (Reload, below) may replace it before the plan is applied. If
		// we baked the pre-overlay endpoint into compiled.Plan now, the
		// Sidecar apply boundary would recompute the managed dest with
		// the overlaid endpoint, WithObservabilityV8ManagedAIDDestination
		// would see the two endpoints disagree, and the reload would
		// fail with "generated managed-enterprise destination rejected".
		// Reload applies the transform post-overlay instead.
		source.compiledV8 = compiled
		return next, source, nil
	}
	return nil, configReloadSource{}, fmt.Errorf(
		"config reload source changed during capture after %d attempts; retry after the writer is idle",
		configReloadSnapshotAttempts,
	)
}

func cloneConfigReloadSource(source configReloadSource) configReloadSource {
	source.raw = append([]byte(nil), source.raw...)
	return source
}

type configSnapshotChangedError struct{}

func (configSnapshotChangedError) Error() string {
	return "config source changed while it was being read"
}

func isConfigSnapshotChanged(err error) bool {
	_, ok := err.(configSnapshotChangedError)
	return ok
}

func readConfigFileSnapshot(path string) (configFileSnapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return configFileSnapshot{}, fmt.Errorf("config reload read %s: %w", path, err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return configFileSnapshot{}, fmt.Errorf("config reload stat %s: %w", path, err)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return configFileSnapshot{}, fmt.Errorf("config reload read %s: %w", path, err)
	}
	after, err := file.Stat()
	if err != nil {
		return configFileSnapshot{}, fmt.Errorf("config reload stat %s: %w", path, err)
	}
	if !sameConfigFileInfo(before, after) || int64(len(raw)) != after.Size() {
		return configFileSnapshot{}, configSnapshotChangedError{}
	}
	return configFileSnapshot{raw: raw, info: after}, nil
}

func sameConfigFileSnapshot(left, right configFileSnapshot) bool {
	return bytes.Equal(left.raw, right.raw) && sameConfigFileInfo(left.info, right.info)
}

func sameConfigFileInfo(left, right os.FileInfo) bool {
	if left == nil || right == nil {
		return false
	}
	return os.SameFile(left, right) && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime()) && left.Mode() == right.Mode()
}

func cloneConfig(in *config.Config) *config.Config {
	if in == nil {
		return nil
	}
	// DeepCopy goes through JSON, which preserves the distinction between nil
	// and explicitly empty slices and maps. YAML omitempty round-tripping
	// collapsed those values, causing a freshly loaded snapshot to compare
	// different from the same file on reload and spuriously classify
	// unrelated security sections as changed. DeepCopy also keeps the state
	// JSON drops, such as the standalone AI Defense credential binding the
	// scanners read from the published config (GAP-1483).
	out, err := in.DeepCopy()
	if err != nil {
		panic(fmt.Errorf("config manager: clone config: %w", err))
	}
	return out
}

func (m *ConfigManager) matches(path string) bool {
	return equalConfigPathForDiff(filepath.Clean(path), m.path, runtime.GOOS)
}

// classify reports which watched file the fsnotify event refers to:
// "config" for the primary config.yaml, "env_config" for the AVC-authored
// env_config.json, or "" for anything else in the watched dirs (state
// files, sidecar caches, unrelated writes). We watch entire directories
// rather than files because atomic-write dances (tempfile + rename) fire
// events on the target's *parent*, not the target itself.
func (m *ConfigManager) classify(path string) string {
	cleaned := filepath.Clean(path)
	if equalConfigPathForDiff(cleaned, m.path, runtime.GOOS) {
		return "config"
	}
	if envPath := m.getEnvConfigPath(); envPath != "" && equalConfigPathForDiff(cleaned, filepath.Clean(envPath), runtime.GOOS) {
		return "env_config"
	}
	if equalConfigPathForDiff(cleaned, filepath.Join(filepath.Dir(m.path), configwrite.GenerationFileName), runtime.GOOS) {
		return configGenerationTrigger
	}
	return ""
}

// configGenerationTrigger classifies config.generation.json, which the
// config writer updates next to config.yaml.
const configGenerationTrigger = "generation"

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

// preserveManagedGatewayRuntimeFields carries boot-time-derived runtime
// Gateway fields from oldCfg onto next before diffConfigs runs. Every
// field carried here is either mapstructure:"-" (never present in
// config.yaml) or synthesised at process start; failing to preserve
// them makes diffConfigs report gateway=changed on every reload and
// applyConfigReload rejects the whole reload with
// "config reload requires gateway restart for: gateway".
//
// applyConfigReload has a partial preservation step of its own (Token
// only, line ~1165 in sidecar.go) but it fires AFTER diffing, so it
// can't stop the false restart signal. This helper runs BEFORE the
// diff and is the single source of truth for pre-diff normalisation.
//
// Kept scoped to managed_enterprise per operator direction — the OSS
// reload path is intentionally untouched.
//
// Fields preserved:
//   - Gateway.Token — synthesised by ensureGatewayTokenSynthesis on
//     first boot; not written into config.yaml on disk.
//   - Gateway.NoTLS — mapstructure:"-", set at boot from RequiresTLS.
//     Runtime state, not user-configurable.
//   - Gateway.ClawHome — mapstructure:"-", derived from
//     os.UserHomeDir() at Load time. Stable across reloads on the same
//     host but the initial cached snapshot may have been rendered before
//     the derivation ran.
//
// nil-safe: no-op when oldCfg or next is nil (mirrors diffConfigs'
// early-out for the boot-time / first-load case where nothing to
// preserve).
func preserveManagedGatewayRuntimeFields(oldCfg, next *config.Config) {
	if oldCfg == nil || next == nil {
		return
	}
	if !managed.IsManagedEnterprise(next.DeploymentMode) {
		return
	}
	if strings.TrimSpace(next.Gateway.Token) == "" && strings.TrimSpace(oldCfg.Gateway.Token) != "" {
		next.Gateway.Token = oldCfg.Gateway.Token
	}
	// NoTLS is bool — the "was it set on the runtime side and zeroed
	// by LoadFromFile?" question reduces to "old=true, new=false".
	// Copy that specific transition.
	if oldCfg.Gateway.NoTLS && !next.Gateway.NoTLS {
		next.Gateway.NoTLS = true
	}
	if next.Gateway.ClawHome == "" && oldCfg.Gateway.ClawHome != "" {
		next.Gateway.ClawHome = oldCfg.Gateway.ClawHome
	}
}

func diffConfigs(oldCfg, newCfg *config.Config) ConfigDiff {
	if oldCfg == nil || newCfg == nil {
		return ConfigDiff{Changed: []string{"config"}}
	}
	var changed []string
	add := func(path string, oldVal, newVal any) {
		if !configValuesEqualForDiff(oldVal, newVal, runtime.GOOS) {
			changed = append(changed, path)
		}
	}
	addPath := func(name, oldPath, newPath string) {
		if !equalConfigPathForDiff(oldPath, newPath, runtime.GOOS) {
			changed = append(changed, name)
		}
	}
	add("llm", oldCfg.LLM, newCfg.LLM)
	add("claw", oldCfg.Claw, newCfg.Claw)
	add("agent", oldCfg.Agent, newCfg.Agent)
	add("acp", oldCfg.ACP, newCfg.ACP)
	add("cisco_ai_defense", oldCfg.CiscoAIDefense, newCfg.CiscoAIDefense)
	add("scanners", oldCfg.Scanners, newCfg.Scanners)
	add("watch", oldCfg.Watch, newCfg.Watch)
	add("guardrail", oldCfg.Guardrail, newCfg.Guardrail)
	add("guardrail.retain_judge_bodies", oldCfg.Guardrail.RetainJudgeBodies, newCfg.Guardrail.RetainJudgeBodies)
	// Identity-based guardrail profiles are named on their own so a profile
	// edit is visible in the change summary; they reload hot.
	add("guardrail.profiles",
		[]any{oldCfg.Guardrail.Profiles, oldCfg.Guardrail.ProfileAssignments, oldCfg.Guardrail.DefaultProfile},
		[]any{newCfg.Guardrail.Profiles, newCfg.Guardrail.ProfileAssignments, newCfg.Guardrail.DefaultProfile})
	oldEffectiveGateway := effectiveGatewayConfigForDiff(oldCfg.Gateway)
	newEffectiveGateway := effectiveGatewayConfigForDiff(newCfg.Gateway)
	add("gateway", oldEffectiveGateway, newEffectiveGateway)
	add("openshell", oldCfg.OpenShell, newCfg.OpenShell)
	// The v8 action keys of a Secure Client source, which main compared here;
	// no Secure Client hot set lists them, so an edit is restart-required.
	for _, key := range []string{"skill_actions", "mcp_actions", "plugin_actions"} {
		add(key, oldCfg.SecureClientV8Actions[key], newCfg.SecureClientV8Actions[key])
	}
	add("admission", oldCfg.Admission, newCfg.Admission)
	add("asset_policy", oldCfg.AssetPolicy, newCfg.AssetPolicy)
	add("registries", oldCfg.Registries, newCfg.Registries)
	add("connector_hooks", oldCfg.ConnectorHooks, newCfg.ConnectorHooks)
	add("webhooks", oldCfg.Webhooks, newCfg.Webhooks)
	add("observability", oldCfg.Observability, newCfg.Observability)
	add("ai_discovery", oldCfg.AIDiscovery, newCfg.AIDiscovery)
	add("application_protection", oldCfg.ApplicationProtection, newCfg.ApplicationProtection)
	add("notifications", oldCfg.Notifications, newCfg.Notifications)
	add("routing", oldCfg.Routing, newCfg.Routing)
	add("llm_providers", oldCfg.LLMProviders, newCfg.LLMProviders)
	add("update", oldCfg.Update, newCfg.Update)
	add("environment", oldCfg.Environment, newCfg.Environment)
	add("tenant_id", oldCfg.TenantID, newCfg.TenantID)
	add("workspace_id", oldCfg.WorkspaceID, newCfg.WorkspaceID)
	add("deployment_mode", oldCfg.DeploymentMode, newCfg.DeploymentMode)
	add("discovery_source", oldCfg.DiscoverySource, newCfg.DiscoverySource)
	addPath("data_dir", oldCfg.DataDir, newCfg.DataDir)
	addPath("audit_db", oldCfg.AuditDB, newCfg.AuditDB)
	addPath("judge_bodies_db", oldCfg.JudgeBodiesDB, newCfg.JudgeBodiesDB)
	// Secure Client keeps the reload classification it had before the
	// configuration generation (issue #1092): the hot set below, a restart
	// for any gateway edit but the reload mode, and every per-connector
	// guardrail setting. Its v8 action keys (skill_actions, mcp_actions,
	// plugin_actions, compared above) are restart-required.
	secureClient := oldCfg.SecureClientIntegration() || newCfg.SecureClientIntegration()
	standalone := oldCfg.StandaloneEnterprise() || newCfg.StandaloneEnterprise()
	if !secureClient {
		// The directory keys, which main did not compare (Secure Client keeps
		// that). policy_dir is generation input (the Rego modules and their
		// watch) and quarantine_dir restarts the install watcher in-process,
		// so both are hot; plugin_dir is restart-required: the connector
		// registry discovers its plugins when the guardrail starts.
		addPath("policy_dir", oldCfg.PolicyDir, newCfg.PolicyDir)
		addPath("quarantine_dir", oldCfg.QuarantineDir, newCfg.QuarantineDir)
		addPath("plugin_dir", oldCfg.PluginDir, newCfg.PluginDir)
	}
	if standalone {
		// The standalone profile keeps its runtime settings in the enterprise
		// block. The AI Defense client (enterprise.inspection) is rebuilt in
		// place. enterprise.network is restart-required: the egress route every
		// other outbound client dials through (webhooks, the LLM passthrough,
		// the remote model router, the telemetry exporters and the Bifrost
		// provider proxies) and the process proxy environment are installed
		// once when the gateway starts, so a hot reload would leave them on the
		// old proxy. Every other enterprise setting (enrollment and the
		// hook-socket authorizer built from it) is also read once at startup.
		// Secure Client deployments carry only the resolved profile, and a
		// profile change is refused before diffing.
		oldEnterprise, newEnterprise := oldCfg.Enterprise, newCfg.Enterprise
		add("enterprise.inspection", oldEnterprise.Inspection, newEnterprise.Inspection)
		add("enterprise.network", oldEnterprise.Network, newEnterprise.Network)
		oldEnterprise.Inspection, newEnterprise.Inspection = config.EnterpriseInspectionConfig{}, config.EnterpriseInspectionConfig{}
		oldEnterprise.Network, newEnterprise.Network = config.EnterpriseNetworkConfig{}, config.EnterpriseNetworkConfig{}
		if standaloneEnrollmentListsHot {
			add("enterprise.enrollment", enrollmentLists(oldEnterprise.Enrollment), enrollmentLists(newEnterprise.Enrollment))
			clearEnrollmentLists(&oldEnterprise.Enrollment)
			clearEnrollmentLists(&newEnterprise.Enrollment)
		}
		add("enterprise", oldEnterprise, newEnterprise)
	}

	// Everything a request decides with reloads hot through the
	// configuration generation (rule packs, rules, levels, profiles, OPA,
	// judge). The rest of this list is the explicit restart set: keys a
	// process-level resource captures once (listeners, stores, identity,
	// the OTel resource): claw (the agent home and config paths the
	// connectors set up from), agent (the identity the agent registry
	// installs once) and routing (the model router process and its port).
	var restart []string
	hotReloadable := map[string]struct{}{
		"acp":                {},
		"guardrail":          {},
		"guardrail.profiles": {},
		"webhooks":           {},
		"observability":      {},
		"notifications":      {},
		// The gateway never reads registry sources (the CLI fetches and
		// promotes them into asset_policy), so a registry add/edit must not
		// make every later reload fail as restart-required (GAP-2422).
		"registries": {},
		// Sandbox settings are read per launch, and the sandbox listeners
		// rebind in-process (apiNeedsRestart).
		"openshell": {},
		// applyConfigReload rebuilds the discovery service and restarts the
		// discovery and runtime-plane workers in-process (aiRestart). Keeping
		// it restart-required failed the whole reload, so a profile edit saved
		// with an ai_discovery edit silently never applied (GAP-0047).
		"ai_discovery": {},
		// Admission and the asset_policy block/allow lists are read from the
		// published config on every decision (watcher, API, hook lanes);
		// providers and update settings are read from the generation or by
		// the CLI.
		"admission":     {},
		"asset_policy":  {},
		"llm_providers": {},
		"update":        {},
		// The judge is rebuilt from llm (judgeChanged), the install watcher
		// restarts in-process for llm, watch and scanners (watcherRestart),
		// and the API and hook scans build their scanners from the live
		// config per request. connector_hooks has no gateway reader.
		"llm":             {},
		"scanners":        {},
		"watch":           {},
		"connector_hooks": {},
		// The levels and packs of application_protection are generation
		// input; its enablement and connector filters apply when the
		// rebuilt discovery service reports (aiDiscoveryNeedsRestart).
		"application_protection": {},
		// The AI Defense clients are rebuilt in place (inspectorNeedsRebuild
		// in applyConfigReload: the hook lane, and the proxy's) and the OTel
		// log sink folds the endpoint (otelNeedsReload).
		"cisco_ai_defense": {},
		// The generation prepares the Rego modules from policy_dir; the
		// install watcher restarts for quarantine_dir (watcherNeedsRestart).
		"policy_dir":     {},
		"quarantine_dir": {},
	}
	if secureClient {
		hotReloadable = map[string]struct{}{
			"acp": {}, "guardrail": {}, "guardrail.profiles": {}, "webhooks": {}, "observability": {},
			"notifications": {}, "registries": {}, "openshell": {}, "cisco_ai_defense": {},
		}
	}
	// standalone: inspectorNeedsRebuild covers the enterprise AI Defense
	// settings, so they stay hot. enterprise.network is restart-required
	// (see above).
	if standalone {
		hotReloadable["enterprise.inspection"] = struct{}{}
		if standaloneEnrollmentListsHot {
			hotReloadable["enterprise.enrollment"] = struct{}{}
		}
	}
	for _, path := range changed {
		if path == "guardrail" && onlyRetainJudgeBodiesChanged(oldCfg, newCfg) {
			// Report the exact restart boundary below instead of the broad
			// guardrail section when this is the only guardrail change.
			continue
		}
		if path == "guardrail.retain_judge_bodies" {
			restart = append(restart, path)
			continue
		}
		if path == "guardrail" && guardrailNeedsRestart(oldCfg, newCfg) {
			restart = append(restart, path)
			continue
		}
		if path == "gateway" && (!secureClient || onlyConfigReloadModeChanged(oldCfg, newCfg)) {
			// gateway.config_reload is read per reload and gateway.watcher
			// restarts the install watcher in-process; every other gateway
			// key (listeners, TLS, device key, token) is process-level.
			continue
		}
		if _, ok := hotReloadable[path]; !ok {
			restart = append(restart, path)
		}
	}
	if !equalConfigPathForDiff(oldCfg.Gateway.DeviceKeyFile, newCfg.Gateway.DeviceKeyFile, runtime.GOOS) {
		restart = append(restart, "gateway.device_key_file")
	}
	oldGateway := oldEffectiveGateway
	newGateway := newEffectiveGateway
	oldGateway.ConfigReload, newGateway.ConfigReload = config.GatewayConfigReloadConfig{}, config.GatewayConfigReloadConfig{}
	if !secureClient {
		oldGateway.Watcher, newGateway.Watcher = config.GatewayWatcherConfig{}, config.GatewayWatcherConfig{}
	}
	if !configValuesEqualForDiff(oldGateway, newGateway, runtime.GOOS) {
		restart = append(restart, "gateway")
	}
	if oldCfg.Guardrail.ScannerMode != newCfg.Guardrail.ScannerMode {
		restart = append(restart, "guardrail.scanner_mode")
	}
	// The connector set (guardrail.connectors membership and enabled) applies
	// in-process: the reload re-runs the connector setup and restarts the
	// install watcher. Secure Client keeps its restart for every connector
	// setting (issue #1092).
	connectorsChanged := secureClient && !reflect.DeepEqual(oldCfg.Guardrail.Connectors, newCfg.Guardrail.Connectors)
	if oldCfg.Guardrail.Connector != newCfg.Guardrail.Connector || connectorsChanged {
		restart = append(restart, "guardrail.connectors")
	}
	return ConfigDiff{Changed: changed, RestartRequired: sortedUniqueStrings(restart)}
}

// standaloneEnrollmentListsHot reports that who is enrolled
// (enterprise.enrollment's user and group lists) reloads in place. A Windows
// gateway reads them nowhere: it has no hook-socket authorizer (that is
// api_uds_unix.go, built once at start), its install watcher follows the
// guardian's authorization record, and the enumerator and the guardian apply
// the lists themselves. Before, such an edit was held at its running value,
// so a config-only ensure never saw the gateway adopt it and ran the full
// upgrade, every service stopped (GAP-0716). A seam for tests.
var standaloneEnrollmentListsHot = runtime.GOOS == "windows"

// enrollmentLists is the part of enrollment that standaloneEnrollmentListsHot
// covers.
func enrollmentLists(e config.EnterpriseEnrollmentConfig) [5][]string {
	return [5][]string{e.IncludeUsers, e.ExcludeUsers, e.IncludeGroups, e.ExcludeGroups, e.ExemptUsers}
}

func clearEnrollmentLists(e *config.EnterpriseEnrollmentConfig) {
	e.IncludeUsers, e.ExcludeUsers, e.IncludeGroups, e.ExcludeGroups, e.ExemptUsers = nil, nil, nil, nil, nil
}

// holdRestartRequired returns next with every restart-required section at
// its running value, or nil when a path can not be held: the storage paths,
// which the compiled observability plan of the candidate already carries, and
// the deployment mode, which the managed destination of that plan is built
// from. Such a reload still fails as restart-required.
func holdRestartRequired(running, next *config.Config, restart []string) *config.Config {
	if running == nil || next == nil {
		return nil
	}
	held := cloneConfig(next)
	for _, path := range restart {
		switch path {
		case "claw":
			held.Claw = running.Claw
		case "agent":
			held.Agent = running.Agent
		case "routing":
			held.Routing = running.Routing
		case "gateway", "gateway.device_key_file":
			reload, watcher := held.Gateway.ConfigReload, held.Gateway.Watcher
			held.Gateway = running.Gateway
			held.Gateway.ConfigReload, held.Gateway.Watcher = reload, watcher
		case "guardrail", "guardrail.retain_judge_bodies", "guardrail.scanner_mode", "guardrail.connectors":
			holdGuardrailProcessSettings(&held.Guardrail, running.Guardrail)
		case "environment", "tenant_id", "workspace_id", "discovery_source":
			// The OTel resource identity the provider factory captured at start.
			held.Environment, held.TenantID = running.Environment, running.TenantID
			held.WorkspaceID, held.DiscoverySource = running.WorkspaceID, running.DiscoverySource
		case "enterprise", "enterprise.network":
			// Enrollment, the hook-socket authorizer and the egress route are
			// installed at start; enterprise.inspection stays hot.
			inspection := held.Enterprise.Inspection
			held.Enterprise = running.Enterprise
			held.Enterprise.Inspection = inspection
		case "plugin_dir":
			held.PluginDir = running.PluginDir
		default:
			return nil
		}
	}
	return held
}

// holdGuardrailProcessSettings puts the guardrailNeedsRestart fields of g
// back to their running values; the policy keys keep the new values.
func holdGuardrailProcessSettings(g *config.GuardrailConfig, running config.GuardrailConfig) {
	g.Host, g.Port, g.Enabled, g.Connector = running.Host, running.Port, running.Enabled, running.Connector
	g.ScannerMode, g.RetainJudgeBodies = running.ScannerMode, running.RetainJudgeBodies
	g.HookSelfHeal, g.HookSelfHealDebounceMs = running.HookSelfHeal, running.HookSelfHealDebounceMs
}

// effectiveGatewayConfigForDiff compares operator-controlled gateway state.
// First boot may synthesize the token into memory and the process environment
// before the startup watcher reloads the unchanged token_env-backed file; those
// forms are operationally identical. NewSidecar also derives NoTLS from the
// gateway and sandbox topology after loading the file, so it is runtime state,
// not a configuration change. TokenEnv remains in the comparison, which keeps
// custody changes and effective-secret changes restart-required.
func effectiveGatewayConfigForDiff(gateway config.GatewayConfig) config.GatewayConfig {
	gateway.Token = gateway.ResolvedToken()
	gateway.NoTLS = false
	return gateway
}

func onlyRetainJudgeBodiesChanged(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil || oldCfg.Guardrail.RetainJudgeBodies == newCfg.Guardrail.RetainJudgeBodies {
		return false
	}
	oldGuardrail := oldCfg.Guardrail
	newGuardrail := newCfg.Guardrail
	oldGuardrail.RetainJudgeBodies = newGuardrail.RetainJudgeBodies
	return configValuesEqualForDiff(oldGuardrail, newGuardrail, runtime.GOOS)
}

func sortedUniqueStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
