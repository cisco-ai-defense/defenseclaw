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
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const configReloadDebounce = 500 * time.Millisecond

const configReloadSnapshotAttempts = 3

const configReloadStartupQuietPeriod = 25 * time.Millisecond

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
	path            string
	applySnapshot   configSnapshotApplyFunc
	logger          *audit.Logger
	health          *SidecarHealth
	loadSnapshot    configSnapshotLoader
	readSnapshot    configFileSnapshotReader
	v8PlanDigest    string
	v8Plan          *config.ObservabilityV8Plan
	afterWatchAdded func()
	observabilityV8 hookLifecycleMetricV8Runtime

	current atomic.Value // *config.Config
	gen     atomic.Uint64
	mu      sync.Mutex
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
		loadSnapshot:  config.LoadRuntimeV8CandidateFromBytes,
		readSnapshot:  readConfigFileSnapshot,
	}
	if initial != nil {
		m.current.Store(cloneConfig(initial))
	}
	if initial != nil && initial.ConfigVersion == config.ObservabilityV8ConfigVersion {
		m.v8PlanDigest = strings.TrimSpace(initialV8PlanDigest)
	}
	return m
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

func (m *ConfigManager) run(ctx context.Context, startupReady chan<- error) error {
	if m == nil {
		if startupReady != nil {
			startupReady <- nil
			close(startupReady)
		}
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
		signalConfigStartupReady(startupReady, err)
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{"path": m.path})
		}
		return fmt.Errorf("config watcher: %w", err)
	}
	defer fsw.Close()

	dir := filepath.Dir(m.path)
	if err := fsw.Add(dir); err != nil {
		signalConfigStartupReady(startupReady, err)
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{"path": m.path})
		}
		return fmt.Errorf("config watcher: watch %s: %w", dir, err)
	}
	if m.afterWatchAdded != nil {
		m.afterWatchAdded()
	}
	if startupReady != nil {
		if err := m.reconcileStartup(ctx, fsw); err != nil {
			signalConfigStartupReady(startupReady, err)
			return err
		}
		signalConfigStartupReady(startupReady, nil)
	}

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	pending := false
	for {
		select {
		case <-ctx.Done():
			if m.health != nil {
				m.health.SetConfig(StateStopped, "", map[string]interface{}{"path": m.path})
			}
			return ctx.Err()
		case event := <-fsw.Events:
			if !m.matches(event.Name) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
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
			pending = false
			if err := m.Reload(ctx, "fsnotify"); err != nil {
				fmt.Fprintf(os.Stderr, "[config] reload failed: %v\n", err)
			}
		}
	}
}

func (m *ConfigManager) reconcileStartup(ctx context.Context, fsw *fsnotify.Watcher) error {
	if m == nil || fsw == nil {
		return fmt.Errorf("config startup reconciliation is unavailable")
	}
	for {
		if err := m.Reload(ctx, "startup_reconcile"); err != nil {
			return err
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
				if m.matches(event.Name) && event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					dirty = true
				}
			case watchErr := <-fsw.Errors:
				if watchErr != nil && m.health != nil {
					m.health.SetConfig(StateError, watchErr.Error(), map[string]interface{}{"path": m.path})
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

func signalConfigStartupReady(ready chan<- error, err error) {
	if ready == nil {
		return
	}
	ready <- err
	close(ready)
}

func (m *ConfigManager) Reload(ctx context.Context, reason string) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	oldCfg := m.Current()
	next, source, err := m.loadStableCandidate(ctx)
	if err != nil {
		m.recordLoadError(ctx, "candidate_invalid")
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
			})
		}
		return err
	}
	if oldCfg == nil || oldCfg.ConfigVersion != config.ObservabilityV8ConfigVersion ||
		next.ConfigVersion != config.ObservabilityV8ConfigVersion {
		m.recordLoadError(ctx, "schema_version")
		return fmt.Errorf("config reload requires schema v8; run 'defenseclaw upgrade' first")
	}
	if oldCfg != nil && managed.IsManagedEnterprise(oldCfg.DeploymentMode) && !managed.IsManagedEnterprise(next.DeploymentMode) {
		m.recordLoadError(ctx, "managed_downgrade")
		return fmt.Errorf("config reload cannot downgrade deployment_mode from managed_enterprise")
	}
	diff := diffConfigs(oldCfg, next)
	if source.compiledV8 != nil && source.compiledV8.Plan != nil && m.observabilityV8PlanChanged(source.compiledV8.Plan) {
		diff.Changed = sortedUniqueStrings(append(diff.Changed, "observability"))
	}
	if len(diff.Changed) == 0 {
		if source.compiledV8 != nil && source.compiledV8.Plan != nil {
			m.v8PlanDigest = source.compiledV8.Plan.Digest()
			m.v8Plan = source.compiledV8.Plan
		}
		version.SetContentHash(source.raw)
		if m.health != nil {
			m.health.SetConfig(StateRunning, "", map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
				"changed":    []string{},
			})
		}
		return nil
	}
	if m.applySnapshot == nil {
		m.recordLoadError(ctx, "apply_unavailable")
		return fmt.Errorf("config reload schema v8 requires a source-aware apply callback")
	}
	applyErr := m.applySnapshot(ctx, oldCfg, next, diff, cloneConfigReloadSource(source))
	if applyErr != nil {
		m.recordLoadError(ctx, "apply_rejected")
		if m.health != nil {
			m.health.SetConfig(StateError, applyErr.Error(), map[string]interface{}{
				"path":             m.path,
				"generation":       m.gen.Load(),
				"reason":           reason,
				"changed":          diff.Changed,
				"restart_required": diff.RestartRequired,
			})
		}
		return applyErr
	}
	gen := m.gen.Add(1)
	m.current.Store(cloneConfig(next))
	if source.compiledV8 != nil && source.compiledV8.Plan != nil {
		m.v8PlanDigest = source.compiledV8.Plan.Digest()
		m.v8Plan = source.compiledV8.Plan
	}
	version.SetContentHash(source.raw)
	if m.logger != nil {
		_ = m.logger.LogActionCtx(ctx, string(audit.ActionConfigUpdate), m.path,
			fmt.Sprintf("generation=%d changed=%s reason=%s", gen, strings.Join(diff.Changed, ","), reason))
	}
	if m.health != nil {
		m.health.SetConfig(StateRunning, "", map[string]interface{}{
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
		defaultDataDir := ""
		if current := m.Current(); current != nil {
			defaultDataDir = current.DataDir
		}
		compiled, compileErr := config.ParseCompileObservabilityV8(
			m.path,
			before.raw,
			config.ObservabilityV8CompileOptions{DefaultDataDir: defaultDataDir},
		)
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
		if next.ConfigVersion != config.ObservabilityV8ConfigVersion {
			return nil, configReloadSource{}, fmt.Errorf("config reload requires schema v8; run 'defenseclaw upgrade' first")
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
		// ConfigManager owns plan comparison and persistence. Inject the
		// release-owned managed destination here, from the fully defaulted and
		// environment-resolved candidate, so both sides of its digest/equivalence
		// comparison have the same generated shape. The Sidecar apply boundary
		// repeats this operation defensively; the plan transform is idempotent.
		if err := applySidecarObservabilityV8ManagedDestination(
			compiled,
			sidecarObservabilityV8ManagedOptionsFromConfig(next),
		); err != nil {
			return nil, configReloadSource{}, fmt.Errorf(
				"config reload observability v8 managed destination: %w", err,
			)
		}
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

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
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
	add("guardrail.retain_judge_bodies", oldCfg.Guardrail.RetainJudgeBodies, newCfg.Guardrail.RetainJudgeBodies)
	oldEffectiveGateway := effectiveGatewayConfigForDiff(oldCfg.Gateway)
	newEffectiveGateway := effectiveGatewayConfigForDiff(newCfg.Gateway)
	add("gateway", oldEffectiveGateway, newEffectiveGateway)
	add("openshell", oldCfg.OpenShell, newCfg.OpenShell)
	add("skill_actions", oldCfg.SkillActions, newCfg.SkillActions)
	add("mcp_actions", oldCfg.MCPActions, newCfg.MCPActions)
	add("plugin_actions", oldCfg.PluginActions, newCfg.PluginActions)
	add("asset_policy", oldCfg.AssetPolicy, newCfg.AssetPolicy)
	add("registries", oldCfg.Registries, newCfg.Registries)
	add("connector_hooks", oldCfg.ConnectorHooks, newCfg.ConnectorHooks)
	add("webhooks", oldCfg.Webhooks, newCfg.Webhooks)
	add("observability", oldCfg.Observability, newCfg.Observability)
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
		"webhooks":         {},
		"observability":    {},
		"notifications":    {},
		"environment":      {},
		"tenant_id":        {},
		"workspace_id":     {},
		"discovery_source": {},
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
	oldGateway := oldEffectiveGateway
	newGateway := newEffectiveGateway
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
	// The provider factory captures these resource-identity values once at
	// process bootstrap. A plan-only graph reload cannot safely rewrite them;
	// publishing the Config as hot would make exported telemetry retain stale
	// identity. Require a process restart until provider-factory replacement is
	// part of the transaction.
	if oldCfg.ConfigVersion == config.ObservabilityV8ConfigVersion &&
		newCfg.ConfigVersion == config.ObservabilityV8ConfigVersion {
		for _, identity := range []struct {
			path    string
			changed bool
		}{
			{path: "environment", changed: oldCfg.Environment != newCfg.Environment},
			{path: "tenant_id", changed: oldCfg.TenantID != newCfg.TenantID},
			{path: "workspace_id", changed: oldCfg.WorkspaceID != newCfg.WorkspaceID},
			{path: "discovery_source", changed: oldCfg.DiscoverySource != newCfg.DiscoverySource},
		} {
			if identity.changed {
				restart = append(restart, identity.path)
			}
		}
	}
	return ConfigDiff{Changed: changed, RestartRequired: sortedUniqueStrings(restart)}
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
	return reflect.DeepEqual(oldGuardrail, newGuardrail)
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
