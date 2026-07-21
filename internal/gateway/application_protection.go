// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const applicationProtectionStateFile = "application_protection_state.json"

type applicationProtectionController struct {
	sidecar   *Sidecar
	registry  *connector.Registry
	apiToken  string
	proxyAddr string
	apiAddr   string
	masterKey string
	cache     *guardrail.RulePackCache

	mu         sync.Mutex
	activeAuto map[string]applicationProtectionActiveRow
	guards     map[string]*HookConfigGuard
	lastErrors map[string]string
}

type applicationProtectionState struct {
	Version    int                               `json:"version"`
	UpdatedAt  string                            `json:"updated_at"`
	Enabled    bool                              `json:"enabled"`
	LastScan   string                            `json:"last_scan,omitempty"`
	Discovered []applicationProtectionSignalRow  `json:"discovered,omitempty"`
	Active     []applicationProtectionActiveRow  `json:"active,omitempty"`
	Skipped    []applicationProtectionSkippedRow `json:"skipped,omitempty"`
	LastErrors map[string]string                 `json:"last_activation_errors,omitempty"`
}

type applicationProtectionSignalRow struct {
	Connector  string  `json:"connector"`
	Name       string  `json:"name,omitempty"`
	Confidence float64 `json:"confidence"`
	State      string  `json:"state,omitempty"`
	LastSeen   string  `json:"last_seen,omitempty"`
	Detector   string  `json:"detector,omitempty"`
	SignalID   string  `json:"signal_id,omitempty"`
}

type applicationProtectionActiveRow struct {
	Connector   string `json:"connector"`
	Source      string `json:"source"`
	ActivatedAt string `json:"activated_at,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
}

type applicationProtectionSkippedRow struct {
	Connector  string  `json:"connector"`
	Reason     string  `json:"reason"`
	Detail     string  `json:"detail,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	LastSeen   string  `json:"last_seen,omitempty"`
}

func newApplicationProtectionController(s *Sidecar, registry *connector.Registry, apiToken, proxyAddr, apiAddr, masterKey string) *applicationProtectionController {
	c := &applicationProtectionController{
		sidecar:    s,
		registry:   registry,
		apiToken:   apiToken,
		proxyAddr:  proxyAddr,
		apiAddr:    apiAddr,
		masterKey:  masterKey,
		cache:      guardrail.NewRulePackCache(),
		activeAuto: map[string]applicationProtectionActiveRow{},
		guards:     map[string]*HookConfigGuard{},
		lastErrors: map[string]string{},
	}
	for _, row := range loadApplicationProtectionState(s.cfg.DataDir).Active {
		if row.Source != "automatic" {
			continue
		}
		name := normalizeAppProtectionConnector(row.Connector)
		if name == "" {
			continue
		}
		row.Connector = name
		c.activeAuto[name] = row
	}
	return c
}

func (c *applicationProtectionController) UpdateRuntime(registry *connector.Registry, apiToken, proxyAddr, apiAddr, masterKey string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if registry != nil {
		c.registry = registry
	}
	c.apiToken = apiToken
	c.proxyAddr = proxyAddr
	c.apiAddr = apiAddr
	c.masterKey = masterKey
}

func (c *applicationProtectionController) OnDiscoveryReport(ctx context.Context, report inventory.AIDiscoveryReport) {
	if c == nil || c.sidecar == nil || c.sidecar.cfg == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	cfg := c.sidecar.cfg
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		state := applicationProtectionState{
			Version:    1,
			UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
			Enabled:    cfg.ApplicationProtection.Enabled,
			LastScan:   formatTimeRFC3339(report.Summary.ScannedAt),
			Active:     c.activeRowsLocked(),
			LastErrors: copyStringMap(c.lastErrors),
		}
		c.publishStateLocked(state, StateDisabled, "managed_enterprise automatic protection is handled by the enterprise hooks guardian; the sandboxed gateway will not write user homes")
		return
	}
	if !cfg.ApplicationProtection.Enabled {
		state := applicationProtectionState{
			Version:    1,
			UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
			Enabled:    false,
			LastScan:   formatTimeRFC3339(report.Summary.ScannedAt),
			Active:     c.activeRowsLocked(),
			LastErrors: copyStringMap(c.lastErrors),
		}
		c.publishStateLocked(state, StateDisabled, "application protection disabled")
		return
	}

	signals := bestSupportedConnectorSignals(report)
	discovered := make([]applicationProtectionSignalRow, 0, len(signals))
	skipped := make([]applicationProtectionSkippedRow, 0)
	now := time.Now().UTC()

	for _, sig := range signals {
		name := normalizeAppProtectionConnector(sig.SupportedConnector)
		if name == "" {
			continue
		}
		discovered = append(discovered, signalRow(name, sig))
		conn, ok := c.registry.Get(name)
		if !ok {
			skipped = append(skipped, skippedRow(name, "unknown_connector", "connector is not registered", sig))
			continue
		}
		if cfg.ManualConnectorConfigured(name) {
			skipped = append(skipped, skippedRow(name, "manual_connector_configured", "connector source is manual setup", sig))
			continue
		}
		if !connector.ConnectorSupportedOnHostOS(conn.Name()) {
			skipped = append(skipped, skippedRow(name, "unsupported_os", "connector is not supported on this host OS", sig))
			continue
		}
		if proxyShouldBindForConnector(conn, &cfg.Guardrail) || connector.IsProxyConnector(conn.Name()) {
			skipped = append(skipped, skippedRow(name, "proxy_connector_setup_only", "proxy connectors remain setup-only", sig))
			continue
		}
		if !cfg.ApplicationProtection.AllowsConnector(name) {
			skipped = append(skipped, skippedRow(name, "connector_filtered", "connector excluded by application_protection include/exclude policy", sig))
			continue
		}
		if !cfg.ApplicationProtection.EffectiveEnabled(name) {
			skipped = append(skipped, skippedRow(name, "connector_disabled", "application_protection connector override disabled this connector", sig))
			continue
		}

		if strings.EqualFold(sig.State, "gone") {
			if c.shouldRemoveGoneConnector(sig, now) {
				if err := c.teardownAutoConnectorLocked(ctx, conn); err != nil {
					c.lastErrors[name] = err.Error()
					skipped = append(skipped, skippedRow(name, "gone_teardown_error", err.Error(), sig))
					continue
				}
				delete(c.activeAuto, name)
				delete(c.lastErrors, name)
				skipped = append(skipped, skippedRow(name, "gone_removed", "connector disappeared and remove_when_gone=true", sig))
			} else if _, active := c.activeAuto[name]; active {
				c.refreshActiveLocked(name, sig)
				skipped = append(skipped, skippedRow(name, "gone_retained", "connector disappeared but hooks are retained by policy", sig))
			} else {
				skipped = append(skipped, skippedRow(name, "gone", "connector is no longer detected", sig))
			}
			continue
		}

		minConfidence := cfg.ApplicationProtection.EffectiveMinConfidence(name)
		if sig.Confidence < minConfidence {
			if _, active := c.activeAuto[name]; active {
				c.refreshActiveLocked(name, sig)
				skipped = append(skipped, skippedRow(name, "confidence_below_threshold_retained", fmt.Sprintf("confidence %.2f below threshold %.2f; existing hooks retained", sig.Confidence, minConfidence), sig))
			} else {
				skipped = append(skipped, skippedRow(name, "confidence_below_threshold", fmt.Sprintf("confidence %.2f below threshold %.2f", sig.Confidence, minConfidence), sig))
			}
			continue
		}
		if strings.EqualFold(cfg.EffectiveGuardrailModeForConnector(name), "action") {
			opts, err := c.sidecar.connectorSetupOptsChecked(conn, c.apiToken, c.proxyAddr, c.apiAddr)
			if err != nil {
				skipped = append(skipped, skippedRow(name, "scoped_token_error", err.Error(), sig))
				continue
			}
			if ok, reason, detail := c.hookContractPreflightLocked(conn, opts); !ok {
				delete(c.lastErrors, name)
				skipped = append(skipped, skippedRow(name, reason, detail, sig))
				continue
			}
		}

		if _, active := c.activeAuto[name]; !active {
			opts, err := c.sidecar.connectorSetupOptsChecked(conn, c.apiToken, c.proxyAddr, c.apiAddr)
			if err != nil {
				skipped = append(skipped, skippedRow(name, "scoped_token_error", err.Error(), sig))
				continue
			}
			if ok, detail, err := activationSurfaceExists(conn, opts); err != nil {
				skipped = append(skipped, skippedRow(name, "hook_config_check_error", err.Error(), sig))
				continue
			} else if !ok {
				skipped = append(skipped, skippedRow(name, "hook_config_missing", detail, sig))
				continue
			}
			if ok, reason, detail := c.hookContractPreflightLocked(conn, opts); !ok {
				delete(c.lastErrors, name)
				skipped = append(skipped, skippedRow(name, reason, detail, sig))
				continue
			}
		} else if c.sidecar.health == nil || !c.sidecar.health.HasConnector(name) {
			opts, err := c.sidecar.connectorSetupOptsChecked(conn, c.apiToken, c.proxyAddr, c.apiAddr)
			if err != nil {
				skipped = append(skipped, skippedRow(name, "scoped_token_error", err.Error(), sig))
				continue
			}
			if ok, reason, detail := c.hookContractPreflightLocked(conn, opts); !ok {
				delete(c.lastErrors, name)
				skipped = append(skipped, skippedRow(name, reason, detail, sig))
				continue
			}
		}

		if err := c.ensureAutoConnectorLocked(ctx, conn, sig, now); err != nil {
			c.lastErrors[name] = err.Error()
			skipped = append(skipped, skippedRow(name, "activation_error", err.Error(), sig))
			continue
		}
		delete(c.lastErrors, name)
	}

	state := applicationProtectionState{
		Version:    1,
		UpdatedAt:  now.Format(time.RFC3339),
		Enabled:    true,
		LastScan:   formatTimeRFC3339(report.Summary.ScannedAt),
		Discovered: sortSignalRows(discovered),
		Active:     c.activeRowsLocked(),
		Skipped:    sortSkippedRows(skipped),
		LastErrors: copyStringMap(c.lastErrors),
	}
	c.publishStateLocked(state, StateRunning, "")
}

func (c *applicationProtectionController) ensureAutoConnectorLocked(ctx context.Context, conn connector.Connector, sig inventory.AISignal, now time.Time) error {
	name := conn.Name()
	if _, active := c.activeAuto[name]; active && c.sidecar.health != nil && c.sidecar.health.HasConnector(name) {
		c.refreshActiveLocked(name, sig)
		c.startGuardLocked(ctx, conn)
		return nil
	}
	opts, err := c.sidecar.connectorSetupOptsChecked(conn, c.apiToken, c.proxyAddr, c.apiAddr)
	if err != nil {
		return err
	}
	if err := c.sidecar.setupOneConnector(ctx, conn, opts, c.masterKey, c.cache); err != nil {
		recordAndRollbackFailedConnectorSetup(conn, opts, ctx)
		return err
	}
	c.activeAuto[name] = applicationProtectionActiveRow{
		Connector:   name,
		Source:      "automatic",
		ActivatedAt: now.Format(time.RFC3339),
		LastSeen:    formatTimeRFC3339(sig.LastSeen),
	}
	if c.sidecar.health != nil {
		c.sidecar.health.RegisterConnectorWithSource(name, conn.ToolInspectionMode(), conn.SubprocessPolicy(), "automatic")
	}
	c.startGuardLocked(ctx, conn)
	emitLifecycle(ctx, "application_protection", "activated", map[string]string{
		"connector":  name,
		"confidence": fmt.Sprintf("%.4f", sig.Confidence),
	})
	return nil
}

func activationSurfaceExists(conn connector.Connector, opts connector.SetupOpts) (bool, string, error) {
	paths := connector.HookConfigPathsForConnector(conn, opts)
	if len(paths) == 0 {
		return false, "connector does not expose a hook config path", nil
	}
	missing := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		info, err := os.Stat(path)
		if err == nil {
			if info.IsDir() {
				missing = append(missing, path+" is a directory")
				continue
			}
			return true, path, nil
		}
		if os.IsNotExist(err) {
			missing = append(missing, path)
			continue
		}
		return false, path, fmt.Errorf("check hook config %s: %w", path, err)
	}
	if len(missing) == 0 {
		return false, "connector does not expose a hook config path", nil
	}
	return false, "hook config file not found: " + strings.Join(missing, ", "), nil
}

func (c *applicationProtectionController) refreshActiveLocked(name string, sig inventory.AISignal) {
	row := c.activeAuto[name]
	if row.Connector == "" {
		row.Connector = name
		row.Source = "automatic"
	}
	row.LastSeen = formatTimeRFC3339(sig.LastSeen)
	c.activeAuto[name] = row
	if conn, ok := c.registry.Get(name); ok && c.sidecar.health != nil {
		c.sidecar.health.RegisterConnectorWithSource(name, conn.ToolInspectionMode(), conn.SubprocessPolicy(), "automatic")
	}
}

func (c *applicationProtectionController) startGuardLocked(ctx context.Context, conn connector.Connector) {
	if c == nil || c.sidecar == nil || c.sidecar.cfg == nil || conn == nil {
		return
	}
	if !c.sidecar.cfg.Guardrail.HookSelfHeal {
		return
	}
	if _, exists := c.guards[conn.Name()]; exists {
		return
	}
	debounce := time.Duration(c.sidecar.cfg.Guardrail.HookSelfHealDebounceMs) * time.Millisecond
	metricRuntime, _ := c.sidecar.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	guard := NewHookConfigGuard(c.sidecar.logger, metricRuntime, debounce)
	c.sidecar.bindHookRuntimePolicyResolver(guard)
	guard.SetHealNotifier(c.sidecar.notifyHookHealed)
	opts, err := c.sidecar.connectorSetupOptsChecked(conn, c.apiToken, c.proxyAddr, c.apiAddr)
	if err != nil {
		c.lastErrors[conn.Name()] = err.Error()
		return
	}
	guard.Start(ctx, conn, opts)
	c.guards[conn.Name()] = guard
}

func (c *applicationProtectionController) teardownAutoConnectorLocked(ctx context.Context, conn connector.Connector) error {
	name := conn.Name()
	if guard := c.guards[name]; guard != nil {
		guard.Stop()
		delete(c.guards, name)
	}
	opts, err := c.sidecar.connectorSetupOptsChecked(conn, c.apiToken, c.proxyAddr, c.apiAddr)
	if err != nil {
		return err
	}
	if err := conn.Teardown(ctx, opts); err != nil {
		return fmt.Errorf("connector %s teardown failed: %w", name, err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		return fmt.Errorf("connector %s teardown left stale state: %w", name, err)
	}
	emitLifecycle(ctx, "application_protection", "removed", map[string]string{"connector": name})
	return nil
}

func (c *applicationProtectionController) hookContractPreflightLocked(conn connector.Connector, opts connector.SetupOpts) (bool, string, string) {
	if c == nil || c.sidecar == nil || c.sidecar.cfg == nil || conn == nil {
		return true, "", ""
	}
	cfg := c.sidecar.cfg
	mode := cfg.EffectiveGuardrailModeForConnector(conn.Name())
	if !strings.EqualFold(mode, "action") || os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") == "1" {
		return true, "", ""
	}
	resolution := connector.ResolveHookContract(conn.Name(), opts.AgentVersion)
	if connector.HookContractNeedsActionOverride(resolution) {
		return false, "hook_contract_unverified", fmt.Sprintf("agent version %q is not verified against a known hook contract: %s", opts.AgentVersion, resolution.Reason)
	}
	if previous := connector.LoadHookContractLockEntry(cfg.DataDir, conn.Name()); previous.Connector != "" {
		current := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
		if connector.HookContractLockDrifted(previous, current) {
			return false, "hook_contract_drift", fmt.Sprintf("previous version=%q contract=%s current version=%q contract=%s", previous.RawAgentVersion, previous.ContractID, current.RawAgentVersion, current.ContractID)
		}
	}
	return true, "", ""
}

func (c *applicationProtectionController) shouldRemoveGoneConnector(sig inventory.AISignal, now time.Time) bool {
	if c == nil || c.sidecar == nil || c.sidecar.cfg == nil {
		return false
	}
	cfg := c.sidecar.cfg.ApplicationProtection
	if !cfg.RemoveWhenGone {
		return false
	}
	if sig.LastSeen.IsZero() {
		return cfg.GoneAfterMin == 0
	}
	return now.Sub(sig.LastSeen) >= time.Duration(cfg.GoneAfterMin)*time.Minute
}

func (c *applicationProtectionController) activeRowsLocked() []applicationProtectionActiveRow {
	rows := make([]applicationProtectionActiveRow, 0, len(c.activeAuto))
	for name, row := range c.activeAuto {
		if row.Connector == "" {
			row.Connector = name
		}
		if row.Source == "" {
			row.Source = "automatic"
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Connector < rows[j].Connector })
	return rows
}

func (c *applicationProtectionController) publishStateLocked(state applicationProtectionState, healthState SubsystemState, lastErr string) {
	if c == nil || c.sidecar == nil || c.sidecar.health == nil || c.sidecar.cfg == nil {
		return
	}
	if err := saveApplicationProtectionState(c.sidecar.cfg.DataDir, state); err != nil {
		lastErr = err.Error()
		healthState = StateError
	}
	guardrailMode := "observe"
	assetPolicyMode := "observe"
	if c.sidecar.cfg.ApplicationProtection.Enabled {
		guardrailMode = c.sidecar.cfg.EffectiveGuardrailModeForConnector("__automatic__")
		assetPolicyMode = c.sidecar.cfg.EffectiveAssetPolicyModeForConnector("__automatic__")
	}
	details := map[string]interface{}{
		"enabled":                      state.Enabled,
		"last_scan":                    state.LastScan,
		"discovered":                   state.Discovered,
		"active":                       state.Active,
		"skipped":                      state.Skipped,
		"last_errors":                  state.LastErrors,
		"state_file":                   filepath.Join(c.sidecar.cfg.DataDir, applicationProtectionStateFile),
		"guardrail_mode":               guardrailMode,
		"asset_policy_mode":            assetPolicyMode,
		"require_trusted_binary_paths": c.sidecar.cfg.AIDiscovery.RequireTrustedBinaryPaths,
		"trusted_binary_prefixes":      append([]string{}, c.sidecar.cfg.AIDiscovery.TrustedBinaryPrefixes...),
	}
	c.sidecar.health.SetApplicationProtection(healthState, lastErr, details)
}

func bestSupportedConnectorSignals(report inventory.AIDiscoveryReport) []inventory.AISignal {
	best := map[string]inventory.AISignal{}
	for _, sig := range report.Signals {
		if sig.Category != inventory.SignalSupportedConnector {
			continue
		}
		name := normalizeAppProtectionConnector(sig.SupportedConnector)
		if name == "" {
			continue
		}
		prev, ok := best[name]
		if !ok || signalBetter(sig, prev) {
			best[name] = sig
		}
	}
	names := make([]string, 0, len(best))
	for name := range best {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]inventory.AISignal, 0, len(names))
	for _, name := range names {
		out = append(out, best[name])
	}
	return out
}

func signalBetter(candidate, current inventory.AISignal) bool {
	if !strings.EqualFold(candidate.State, current.State) {
		if !strings.EqualFold(candidate.State, "gone") {
			return true
		}
		if strings.EqualFold(current.State, "gone") {
			return candidate.LastSeen.After(current.LastSeen)
		}
		return false
	}
	if candidate.Confidence != current.Confidence {
		return candidate.Confidence > current.Confidence
	}
	return candidate.LastSeen.After(current.LastSeen)
}

func signalRow(connectorName string, sig inventory.AISignal) applicationProtectionSignalRow {
	return applicationProtectionSignalRow{
		Connector:  connectorName,
		Name:       sig.Name,
		Confidence: sig.Confidence,
		State:      sig.State,
		LastSeen:   formatTimeRFC3339(sig.LastSeen),
		Detector:   sig.Detector,
		SignalID:   sig.SignalID,
	}
}

func skippedRow(connectorName, reason, detail string, sig inventory.AISignal) applicationProtectionSkippedRow {
	return applicationProtectionSkippedRow{
		Connector:  connectorName,
		Reason:     reason,
		Detail:     detail,
		Confidence: sig.Confidence,
		LastSeen:   formatTimeRFC3339(sig.LastSeen),
	}
}

func sortSignalRows(rows []applicationProtectionSignalRow) []applicationProtectionSignalRow {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Connector < rows[j].Connector })
	return rows
}

func sortSkippedRows(rows []applicationProtectionSkippedRow) []applicationProtectionSkippedRow {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Connector == rows[j].Connector {
			return rows[i].Reason < rows[j].Reason
		}
		return rows[i].Connector < rows[j].Connector
	})
	return rows
}

func normalizeAppProtectionConnector(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "open-hands", "open_hands":
		return "openhands"
	case "claude-code", "claude_code":
		return "claudecode"
	case "gemini-cli", "gemini_cli", "gemini":
		return "geminicli"
	default:
		return n
	}
}

func formatTimeRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func loadApplicationProtectionState(dataDir string) applicationProtectionState {
	if strings.TrimSpace(dataDir) == "" {
		return applicationProtectionState{}
	}
	data, err := os.ReadFile(filepath.Join(dataDir, applicationProtectionStateFile))
	if err != nil {
		return applicationProtectionState{}
	}
	var state applicationProtectionState
	if err := json.Unmarshal(data, &state); err != nil {
		return applicationProtectionState{}
	}
	return state
}

func saveApplicationProtectionState(dataDir string, state applicationProtectionState) error {
	if strings.TrimSpace(dataDir) == "" {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, applicationProtectionStateFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
