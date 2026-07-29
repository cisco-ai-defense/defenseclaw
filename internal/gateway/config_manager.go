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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const configReloadDebounce = 500 * time.Millisecond

type ConfigDiff struct {
	Changed         []string
	RestartRequired []string
}

type configApplyFunc func(ctx context.Context, oldCfg, newCfg *config.Config, diff ConfigDiff) error

type ConfigManager struct {
	path   string
	apply  configApplyFunc
	logger *audit.Logger
	health *SidecarHealth

	// envConfigPath is the AVC-authored env_config.json (see
	// config.DefaultEnvConfigPath). When set, Reload overlays
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

	current atomic.Value // *config.Config
	gen     atomic.Uint64
	mu      sync.Mutex
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

func NewConfigManager(path string, initial *config.Config, logger *audit.Logger, health *SidecarHealth, apply configApplyFunc) *ConfigManager {
	if strings.TrimSpace(path) == "" {
		path = config.ConfigPath()
	}
	m := &ConfigManager{
		path:   filepath.Clean(path),
		apply:  apply,
		logger: logger,
		health: health,
	}
	if initial != nil {
		m.current.Store(cloneConfig(initial))
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

func (m *ConfigManager) Run(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if m.health != nil {
		m.health.SetConfig(StateRunning, "", map[string]interface{}{
			"path":       m.path,
			"generation": m.gen.Load(),
		})
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{"path": m.path})
		}
		return fmt.Errorf("config watcher: %w", err)
	}
	defer fsw.Close()

	dir := filepath.Dir(m.path)
	if err := fsw.Add(dir); err != nil {
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{"path": m.path})
		}
		return fmt.Errorf("config watcher: watch %s: %w", dir, err)
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
	ensureEnvConfigWatched := func() {
		envPath := m.getEnvConfigPath()
		if envPath == "" {
			return
		}
		want := filepath.Dir(filepath.Clean(envPath))
		if want == dir {
			// Same directory as config.yaml — that watch is enough.
			envConfigWatchedDir = want
			return
		}
		if envConfigWatchedDir == want {
			return
		}
		if err := fsw.Add(want); err == nil {
			envConfigWatchedDir = want
			return
		}
		// Add failed — most likely because the directory doesn't
		// exist yet. Try the nearest existing ancestor so a
		// subsequent mkdir of the env_config dir surfaces as a
		// fsnotify Create event we can react to. Silently skip if
		// even that fails; the independent ticker below retries.
		for anc := filepath.Dir(want); anc != "" && anc != "/" && anc != filepath.Dir(anc); anc = filepath.Dir(anc) {
			if err := fsw.Add(anc); err == nil {
				// Record the effective watched dir (the ancestor)
				// so the ticker below skips re-adding it. We do
				// NOT set envConfigWatchedDir = want because that
				// would make classify's dir comparison bogus; the
				// ancestor watch is a "fill in later" placeholder.
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
	for {
		select {
		case <-ctx.Done():
			if m.health != nil {
				m.health.SetConfig(StateStopped, "", map[string]interface{}{"path": m.path})
			}
			return ctx.Err()
		case event := <-fsw.Events:
			which := m.classify(event.Name)
			if which == "" {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if !pending {
				pendingTrigger = which
			}
			pending = true
			resetTimer(timer, configReloadDebounce)
		case err := <-fsw.Errors:
			if err != nil && m.health != nil {
				m.health.SetConfig(StateError, err.Error(), map[string]interface{}{"path": m.path})
			}
		case <-timer.C:
			if !pending {
				continue
			}
			reason := "fsnotify"
			if pendingTrigger != "" {
				reason = "fsnotify:" + pendingTrigger
			}
			pending = false
			pendingTrigger = ""
			if err := m.Reload(ctx, reason); err != nil {
				fmt.Fprintf(os.Stderr, "[config] reload failed: %v\n", err)
			}
			// Piggyback on the reload path — the AVC packaging pipeline
			// may have just created the env_config directory. The
			// independent envWatchRetryTicker below covers the case
			// where NOTHING in config.yaml has changed but env_config
			// arrives on its own timeline.
			ensureEnvConfigWatched()
		case <-envWatchRetryTicker.C:
			ensureEnvConfigWatched()
		}
	}
}

func (m *ConfigManager) Reload(ctx context.Context, reason string) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	oldCfg := m.Current()
	next, err := config.LoadFromFile(m.path)
	if err != nil {
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
			})
		}
		return err
	}
	if oldCfg != nil && managed.IsManagedEnterprise(oldCfg.DeploymentMode) && !managed.IsManagedEnterprise(next.DeploymentMode) {
		return fmt.Errorf("config reload cannot downgrade deployment_mode from managed_enterprise")
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
		if ep, envErr := config.LoadEnvConfigEndpoint(envPath); envErr == nil {
			// The strings.TrimRight("/", ...) call inside
			// NewCiscoDefenseClawInspectClient tolerates a trailing
			// slash; we don't normalise here so the diff engine can
			// see exactly what's on disk.
			next.CiscoAIDefense.Endpoint = ep
		} else if !errors.Is(envErr, config.ErrEnvConfigMissing) {
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
	diff := diffConfigs(oldCfg, next)
	if len(diff.Changed) == 0 {
		if m.health != nil {
			state := StateRunning
			msg := ""
			if envOverlayErr != nil {
				state = StateError
				msg = envOverlayErr.Error()
			}
			m.health.SetConfig(state, msg, map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
				"changed":    []string{},
			})
		}
		return nil
	}
	if m.apply != nil {
		if err := m.apply(ctx, oldCfg, next, diff); err != nil {
			if m.health != nil {
				m.health.SetConfig(StateError, err.Error(), map[string]interface{}{
					"path":             m.path,
					"generation":       m.gen.Load(),
					"reason":           reason,
					"changed":          diff.Changed,
					"restart_required": diff.RestartRequired,
				})
			}
			return err
		}
	}
	gen := m.gen.Add(1)
	m.current.Store(cloneConfig(next))
	if m.logger != nil {
		_ = m.logger.LogActionCtx(ctx, string(audit.ActionConfigUpdate), m.path,
			fmt.Sprintf("generation=%d changed=%s reason=%s", gen, strings.Join(diff.Changed, ","), reason))
	}
	if m.health != nil {
		state := StateRunning
		msg := ""
		if envOverlayErr != nil {
			state = StateError
			msg = envOverlayErr.Error()
		}
		m.health.SetConfig(state, msg, map[string]interface{}{
			"path":             m.path,
			"generation":       gen,
			"reason":           reason,
			"changed":          diff.Changed,
			"restart_required": diff.RestartRequired,
			"last_success":     time.Now().UTC().Format(time.RFC3339),
		})
	}
	return nil
}

func cloneConfig(in *config.Config) *config.Config {
	if in == nil {
		return nil
	}
	// JSON preserves the distinction between nil and explicitly empty slices
	// and maps. YAML omitempty round-tripping collapsed those values, causing a
	// freshly loaded snapshot to compare different from the same file on reload
	// and spuriously classify unrelated security sections as changed.
	data, err := json.Marshal(in)
	if err != nil {
		panic(fmt.Errorf("config manager: clone config: %w", err))
	}
	var out config.Config
	if err := json.Unmarshal(data, &out); err != nil {
		panic(fmt.Errorf("config manager: decode cloned config: %w", err))
	}
	return &out
}

func (m *ConfigManager) matches(path string) bool {
	return filepath.Clean(path) == m.path
}

// classify reports which watched file the fsnotify event refers to:
// "config" for the primary config.yaml, "env_config" for the AVC-authored
// env_config.json, or "" for anything else in the watched dirs (state
// files, sidecar caches, unrelated writes). We watch entire directories
// rather than files because atomic-write dances (tempfile + rename) fire
// events on the target's *parent*, not the target itself.
func (m *ConfigManager) classify(path string) string {
	cleaned := filepath.Clean(path)
	if cleaned == m.path {
		return "config"
	}
	if envPath := m.getEnvConfigPath(); envPath != "" && cleaned == filepath.Clean(envPath) {
		return "env_config"
	}
	return ""
}

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
//   - Gateway.NoTLS — mapstructure:"-", set at boot from
//     RequiresTLSWithMode(&OpenShell). Runtime state, not user-
//     configurable.
//   - Gateway.SandboxHome, Gateway.ClawHome — mapstructure:"-",
//     derived from OpenShell / os.UserHomeDir() at Load time. Stable
//     across reloads on the same host but the initial cached snapshot
//     may have been rendered before every derivation ran.
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
	// Copy that specific transition; the reverse (old=false, new=true)
	// can only happen if the OpenShell mode legitimately flipped,
	// which is a real change.
	if oldCfg.Gateway.NoTLS && !next.Gateway.NoTLS {
		next.Gateway.NoTLS = true
	}
	if next.Gateway.SandboxHome == "" && oldCfg.Gateway.SandboxHome != "" {
		next.Gateway.SandboxHome = oldCfg.Gateway.SandboxHome
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
		if !reflect.DeepEqual(oldVal, newVal) {
			changed = append(changed, path)
		}
	}
	add("llm", oldCfg.LLM, newCfg.LLM)
	add("claw", oldCfg.Claw, newCfg.Claw)
	add("agent", oldCfg.Agent, newCfg.Agent)
	add("cisco_ai_defense", oldCfg.CiscoAIDefense, newCfg.CiscoAIDefense)
	add("scanners", oldCfg.Scanners, newCfg.Scanners)
	add("watch", oldCfg.Watch, newCfg.Watch)
	add("guardrail", oldCfg.Guardrail, newCfg.Guardrail)
	add("gateway", oldCfg.Gateway, newCfg.Gateway)
	add("openshell", oldCfg.OpenShell, newCfg.OpenShell)
	add("skill_actions", oldCfg.SkillActions, newCfg.SkillActions)
	add("mcp_actions", oldCfg.MCPActions, newCfg.MCPActions)
	add("plugin_actions", oldCfg.PluginActions, newCfg.PluginActions)
	add("asset_policy", oldCfg.AssetPolicy, newCfg.AssetPolicy)
	add("registries", oldCfg.Registries, newCfg.Registries)
	add("otel", oldCfg.OTel, newCfg.OTel)
	add("connector_hooks", oldCfg.ConnectorHooks, newCfg.ConnectorHooks)
	add("audit_sinks", oldCfg.AuditSinks, newCfg.AuditSinks)
	add("webhooks", oldCfg.Webhooks, newCfg.Webhooks)
	add("observability", oldCfg.Observability, newCfg.Observability)
	add("privacy", oldCfg.Privacy, newCfg.Privacy)
	add("ai_discovery", oldCfg.AIDiscovery, newCfg.AIDiscovery)
	add("application_protection", oldCfg.ApplicationProtection, newCfg.ApplicationProtection)
	add("notifications", oldCfg.Notifications, newCfg.Notifications)
	add("environment", oldCfg.Environment, newCfg.Environment)
	add("tenant_id", oldCfg.TenantID, newCfg.TenantID)
	add("workspace_id", oldCfg.WorkspaceID, newCfg.WorkspaceID)
	add("deployment_mode", oldCfg.DeploymentMode, newCfg.DeploymentMode)
	add("discovery_source", oldCfg.DiscoverySource, newCfg.DiscoverySource)
	add("data_dir", oldCfg.DataDir, newCfg.DataDir)
	add("audit_db", oldCfg.AuditDB, newCfg.AuditDB)
	add("judge_bodies_db", oldCfg.JudgeBodiesDB, newCfg.JudgeBodiesDB)

	var restart []string
	hotReloadable := map[string]struct{}{
		"guardrail":        {},
		"otel":             {},
		"audit_sinks":      {},
		"webhooks":         {},
		"observability":    {},
		"notifications":    {},
		"environment":      {},
		"tenant_id":        {},
		"workspace_id":     {},
		"discovery_source": {},
	}
	// managed_enterprise: cisco_ai_defense is hot-reloadable. The AID
	// inspector rebuild path (inspectorNeedsRebuild → applyConfigReload)
	// and the OTel log-sink rebuild (otelNeedsReload folds
	// CiscoAIDefense.Endpoint) together cover every field on the
	// struct. Opensource callers keep the pre-existing restart-required
	// behavior so a stray CiscoAIDefense change on that path still
	// forces the operator's attention.
	if managed.IsManagedEnterprise(newCfg.DeploymentMode) {
		hotReloadable["cisco_ai_defense"] = struct{}{}
	}
	for _, path := range changed {
		if path == "guardrail" && guardrailNeedsRestart(oldCfg, newCfg) {
			restart = append(restart, path)
			continue
		}
		if path == "gateway" && onlyConfigReloadModeChanged(oldCfg, newCfg) {
			continue
		}
		if _, ok := hotReloadable[path]; !ok {
			restart = append(restart, path)
		}
	}
	if oldCfg.DataDir != newCfg.DataDir {
		restart = append(restart, "data_dir")
	}
	if oldCfg.AuditDB != newCfg.AuditDB {
		restart = append(restart, "audit_db")
	}
	if oldCfg.JudgeBodiesDB != newCfg.JudgeBodiesDB {
		restart = append(restart, "judge_bodies_db")
	}
	if oldCfg.Gateway.DeviceKeyFile != newCfg.Gateway.DeviceKeyFile {
		restart = append(restart, "gateway.device_key_file")
	}
	oldGateway := oldCfg.Gateway
	newGateway := newCfg.Gateway
	oldGateway.ConfigReload = config.GatewayConfigReloadConfig{}
	newGateway.ConfigReload = config.GatewayConfigReloadConfig{}
	if !reflect.DeepEqual(oldGateway, newGateway) {
		restart = append(restart, "gateway")
	}
	if oldCfg.Guardrail.ScannerMode != newCfg.Guardrail.ScannerMode {
		restart = append(restart, "guardrail.scanner_mode")
	}
	if oldCfg.Guardrail.Connector != newCfg.Guardrail.Connector ||
		!reflect.DeepEqual(oldCfg.Guardrail.Connectors, newCfg.Guardrail.Connectors) {
		restart = append(restart, "guardrail.connectors")
	}
	if oldCfg.DeploymentMode != newCfg.DeploymentMode {
		restart = append(restart, "deployment_mode")
	}
	return ConfigDiff{Changed: changed, RestartRequired: sortedUniqueStrings(restart)}
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
