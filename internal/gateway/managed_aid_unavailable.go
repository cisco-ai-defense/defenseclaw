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
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
)

// managed_enterprise disables every local detector, so Cisco AI Defense is
// the only decision-maker. cisco_ai_defense.unavailable_action lets an
// administrator choose what happens when AI Defense should have inspected a
// request but could not: "allow" (the default) keeps the historical
// fail-open posture, "block" returns a block verdict instead. The helpers
// below are the single place both lanes (hook and proxy) consult.
//
// unavailable_action covers outages. A build with no managed-cloud
// credential factory can never inspect anything, so on such a build the hook
// lane blocks requests that need inspection whatever unavailable_action says.

const (
	// managedAIDUnavailableReason is the verdict reason for a request blocked
	// because AI Defense could not inspect it. It names the setting so an
	// operator reading the audit log knows how to change the posture.
	managedAIDUnavailableReason = "Cisco AI Defense could not inspect this request; blocked by cisco_ai_defense.unavailable_action=block"
	// managedAIDUnsupportedReason is the verdict reason for a request
	// blocked because the running build has no managed-cloud support.
	managedAIDUnsupportedReason = "Cisco AI Defense cannot inspect requests on this build (no managed-cloud support); managed_enterprise blocks requests that need inspection"
	// managedAIDUnavailableFinding tags the block in findings so dashboards
	// can separate it from a policy match returned by AI Defense.
	managedAIDUnavailableFinding = "ai-defense:unavailable"

	managedAIDBlockCauseAction      = "cisco_ai_defense.unavailable_action=block"
	managedAIDBlockCauseUnsupported = "this build has no managed-cloud support"
)

// errManagedAIDNoVerdict is the availability error the managed inspect
// client reports when a call with a valid token got no verdict from AI
// Defense (transport failure, timeout, non-2xx, or an unusable response).
// Only a later real verdict clears it; a token-only probe does not.
var errManagedAIDNoVerdict = errors.New("Cisco AI Defense returned no verdict for the last inspection (transport, HTTP status or response error)")

// managedInspectionSupport is the hook lane's record that the running
// build has no managed-cloud credential factory. The sidecar sets it when it
// wires the API server; an API server built without a sidecar keeps the
// zero value (supported).
type managedInspectionSupport struct {
	unsupported atomic.Bool
}

// SetManagedInspectionUnsupported marks the hook lane as running
// managed_enterprise on a build that can never reach Cisco AI Defense.
func (a *APIServer) SetManagedInspectionUnsupported(unsupported bool) {
	if a == nil {
		return
	}
	a.managedSupport.unsupported.Store(unsupported)
}

// managedInspectionUnsupported reports whether cfg runs managed_enterprise
// on a build with no managed-cloud credential factory.
func managedInspectionUnsupported(cfg *config.Config) bool {
	return cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) && !cloudreg.Registered()
}

// managedAIDEffectiveUnavailableAction is what happens to a request AI
// Defense could not inspect: the configured action, or block on a build
// that can never inspect.
func managedAIDEffectiveUnavailableAction(cfg *config.Config) string {
	if cfg == nil {
		return config.AIDUnavailableActionAllow
	}
	if managedInspectionUnsupported(cfg) {
		return config.AIDUnavailableActionBlock
	}
	return cfg.CiscoAIDefense.EffectiveUnavailableAction()
}

// managedAIDUnavailablePosture is what currently happens to a request AI
// Defense could not inspect, as /health and the Secure Client availability
// report it. Only a connector in action mode enforces the block; observe
// mode records it as would-block and lets the call run uninspected. So
// while no connector the hook handlers evaluate is in action mode the
// posture is allow, whatever managedAIDEffectiveUnavailableAction says.
// health supplies the connectors application protection registered; nil
// means none.
func managedAIDUnavailablePosture(cfg *config.Config, health *SidecarHealth) string {
	action := managedAIDEffectiveUnavailableAction(cfg)
	if action == config.AIDUnavailableActionBlock && !managedAIDHookLaneEnforces(cfg, health) {
		return config.AIDUnavailableActionAllow
	}
	return action
}

// managedAIDHookLaneEnforces reports whether any connector the hook
// handlers evaluate runs its hooks in action mode, with both resolved the
// way the handlers resolve them (agentHookEnabled, codexEnabled,
// claudeCodeEnabled and agentHookMode). A connector is evaluated when it is
// active (guardrail.connectors, guardrail.connector or claw.mode), when
// connector_hooks.<name>.enabled is set, or when application protection
// registered it and is enabled for it; a manual connector that was disabled
// is not. Its mode is connector_hooks.<name>.mode, then the connector's
// guardrail mode. With no connector selected, the generic inspect routes
// follow guardrail.mode.
func managedAIDHookLaneEnforces(cfg *config.Config, health *SidecarHealth) bool {
	if cfg == nil {
		return false
	}
	active := cfg.ActiveConnectors()
	if len(active) == 0 && inspectMode(cfg) == "action" {
		return true
	}
	for _, name := range active {
		if cfg.Guardrail.EffectiveEnabled(name) && managedAIDHookMode(cfg, name) == "action" {
			return true
		}
	}
	// Connectors the handlers evaluate outside the active list: an enabled
	// connector_hooks entry (or the legacy claude_code / codex block), and
	// connectors application protection registered.
	extra := []string{"claudecode", "codex"}
	for name := range cfg.ConnectorHooks {
		extra = append(extra, name)
	}
	if health != nil {
		extra = append(extra, health.ConnectorsWithSource("automatic")...)
	}
	for _, name := range extra {
		if cfg.ManualConnectorConfigured(name) && !cfg.Guardrail.EffectiveEnabled(name) {
			continue
		}
		evaluated := cfg.ConnectorHookConfig(name).Enabled ||
			(health != nil && health.HasConnectorSource(name, "automatic") &&
				cfg.ApplicationProtection.EffectiveEnabled(name))
		if evaluated && managedAIDHookMode(cfg, name) == "action" {
			return true
		}
	}
	return false
}

// managedAIDHookMode resolves a connector's hook mode the way agentHookMode
// does: connector_hooks.<name>.mode, then the connector's guardrail mode.
func managedAIDHookMode(cfg *config.Config, name string) string {
	mode := strings.TrimSpace(cfg.ConnectorHookConfig(name).Mode)
	if mode == "" || strings.EqualFold(mode, "inherit") {
		mode = cfg.EffectiveGuardrailModeForConnector(name)
	}
	return normalizeAgentHookMode(mode)
}

// managedAIDUnavailableReasonBlockable reports whether a managed fail-open
// reason is an availability failure. A request with nothing to inspect is a
// benign skip and stays allowed under either setting.
func managedAIDUnavailableReasonBlockable(reason string) bool {
	return reason == aidFailOpenUnwired || reason == aidFailOpenUnavailable
}

// managedAIDPolicyConfig returns the configuration that governs the
// unavailable action on the hook lane. The live sidecar snapshot wins so a
// config reload takes effect without an API restart; the construction-time
// copy is the fallback for servers built without a config runtime.
func (a *APIServer) managedAIDPolicyConfig() *config.Config {
	if a == nil {
		return nil
	}
	if a.configSnapshot != nil {
		if live := a.configSnapshot(); live != nil {
			return live
		}
	}
	return a.scannerCfg
}

// managedAIDUnavailableHookVerdict returns the block verdict for a managed
// hook-lane request AI Defense could not inspect, or nil to keep the allow
// path. Hook traffic that an administrator excluded with
// scan_hook_surface=false was never meant to reach AI Defense, so it is not
// treated as unavailable.
func (a *APIServer) managedAIDUnavailableHookVerdict(reason string) *ToolInspectVerdict {
	if a == nil || !managedAIDUnavailableReasonBlockable(reason) {
		return nil
	}
	if a.scannerCfg == nil || !a.scannerCfg.CiscoAIDefense.HookSurfaceEnabled() {
		return nil
	}
	if a.managedSupport.unsupported.Load() {
		logManagedAIDUnavailableBlock("hook", reason, managedAIDBlockCauseUnsupported)
		return &ToolInspectVerdict{
			Action:   "block",
			Severity: "HIGH",
			Reason:   managedAIDUnsupportedReason,
			Findings: []string{managedAIDUnavailableFinding},
		}
	}
	cfg := a.managedAIDPolicyConfig()
	if cfg == nil || !cfg.CiscoAIDefense.BlocksWhenUnavailable() {
		return nil
	}
	logManagedAIDUnavailableBlock("hook", reason, managedAIDBlockCauseAction)
	return &ToolInspectVerdict{
		Action:   "block",
		Severity: "HIGH",
		Reason:   managedAIDUnavailableReason,
		Findings: []string{managedAIDUnavailableFinding},
	}
}

// SetManagedUnavailableAction applies cisco_ai_defense.unavailable_action to
// the managed proxy lane. Safe to call while inspections are in flight.
func (g *GuardrailInspector) SetManagedUnavailableAction(action string) {
	if g == nil {
		return
	}
	cfg := config.CiscoAIDefenseConfig{UnavailableAction: action}
	g.managedUnavailableBlock.Store(cfg.BlocksWhenUnavailable())
}

// managedAIDUnavailableVerdict returns the block verdict for a managed
// proxy-lane request AI Defense could not inspect, or nil to keep the allow
// path.
func (g *GuardrailInspector) managedAIDUnavailableVerdict(reason, direction string) *ScanVerdict {
	if g == nil || !g.managedUnavailableBlock.Load() || !managedAIDUnavailableReasonBlockable(reason) {
		return nil
	}
	logManagedAIDUnavailableBlock("proxy/"+normalizeManagedAIDFailOpenDirection(direction), reason, managedAIDBlockCauseAction)
	return &ScanVerdict{
		Action:         "block",
		Severity:       "HIGH",
		Reason:         managedAIDUnavailableReason,
		Findings:       []string{managedAIDUnavailableFinding},
		Scanner:        "ai-defense",
		ScannerSources: []string{"ai-defense"},
	}
}

// SetManagedUnavailableAction forwards cisco_ai_defense.unavailable_action to
// the proxy's managed inspector. A test double inspector is left alone, the
// same contract as SetManagedInspection.
func (p *GuardrailProxy) SetManagedUnavailableAction(action string) {
	if p == nil {
		return
	}
	if g, ok := p.inspector.(*GuardrailInspector); ok {
		g.SetManagedUnavailableAction(action)
	}
}

// logManagedAIDUnavailableBlock is the fail-closed counterpart of
// logManagedAIDSkip: a rate-limited operator line stating that a request was
// blocked because AI Defense could not inspect it, and why it was blocked
// rather than allowed. It shares the skip log's cooldown clock under a
// distinct key.
func logManagedAIDUnavailableBlock(lane, reason, cause string) {
	key := "unavailable-block:" + lane + ":" + reason + ":" + cause
	if !managedAIDLogDue(key) {
		return
	}
	fmt.Fprintf(defaultLogWriter,
		"  [cisco-ai-defense] WARNING: managed_enterprise AID inspection unavailable (lane=%s reason=%s) — request BLOCKED: %s\n",
		lane, normalizeManagedAIDFailOpenReason(reason), cause)
}

// logManagedAIDNoVerdict is the managed inspect client's rate-limited line
// for a call that produced no AI Defense verdict. It names the cause only:
// whether the request is then allowed or blocked is decided and logged by
// the caller (logManagedAIDSkip or logManagedAIDUnavailableBlock), per
// cisco_ai_defense.unavailable_action.
func logManagedAIDNoVerdict(reason, detail string) {
	if !managedAIDLogDue("no-verdict:" + reason) {
		return
	}
	fmt.Fprintf(defaultLogWriter,
		"  [cisco-ai-defense] WARNING: managed_enterprise AID inspection returned no verdict (reason=%s: %s)\n",
		reason, detail)
}

// managedAIDLogDue applies the shared managed AID log cooldown to key.
func managedAIDLogDue(key string) bool {
	now := time.Now()
	managedAIDSkipState.mu.Lock()
	defer managedAIDSkipState.mu.Unlock()
	if now.Sub(managedAIDSkipState.last[key]) < managedAIDSkipCooldown {
		return false
	}
	managedAIDSkipState.last[key] = now
	return true
}

// requireManagedInspectionSupport is the provider gate shared by the single-
// and multi-connector managed_enterprise guardrail boots. Managed mode
// disables every local detector, so a build with no managed-cloud credential
// factory can never inspect anything; the guardrail reports an error instead
// of running with no inspector.
func (s *Sidecar) requireManagedInspectionSupport() error {
	if cloudreg.Registered() {
		return nil
	}
	err := fmt.Errorf(
		"managed_enterprise requires managed-cloud support: %w",
		cloudreg.ErrNoProviderRegistered,
	)
	s.setInspectionAvailability(cloudreg.ErrNoProviderRegistered)
	s.health.SetGuardrail(StateError, err.Error(), nil)
	return err
}

// addManagedInspectionHealth adds the managed inspection state to a
// guardrail health detail map: whether AI Defense can currently be reached,
// what happens to requests it cannot inspect (managedAIDUnavailablePosture),
// and, while it cannot, the cause and a hint that says what happens to tool
// calls. It runs on the guardrail health ticker, so it also rewires a hook
// lane left without an inspector, re-probes an unavailable provider and
// refreshes the Secure Client availability.
func (s *Sidecar) addManagedInspectionHealth(ctx context.Context, detail map[string]interface{}) {
	if s == nil || detail == nil {
		return
	}
	s.retryManagedHookInspector(ctx)
	s.probeManagedInspection(ctx)
	s.publishManagedInspectionHealth()
	available, cause := s.managedInspectionState()
	cfg := s.currentConfig()
	action := managedAIDUnavailablePosture(cfg, s.health)
	detail["inspection_available"] = available
	detail["inspection_unavailable_action"] = action
	if available {
		return
	}
	detail["inspection_error"] = cause
	// enforcement_enabled describes the configured hook mode, so say
	// plainly what is happening behind it.
	if action == config.AIDUnavailableActionBlock {
		detail["hint"] = "remote inspection is unreachable; tool calls that need inspection are being blocked (cisco_ai_defense.unavailable_action=block)"
		return
	}
	if managedAIDEffectiveUnavailableAction(cfg) == config.AIDUnavailableActionBlock {
		detail["hint"] = "remote inspection is unreachable; tool calls are not being inspected (no connector is in action mode, so cisco_ai_defense.unavailable_action=block only records them as would-block)"
		return
	}
	detail["hint"] = "remote inspection is unreachable; tool calls are not being inspected"
}

// managedAIDUnavailablePostureLabel describes the configured unavailable
// action for the managed boot log line.
func managedAIDUnavailablePostureLabel(cfg *config.Config) string {
	if cfg != nil && cfg.CiscoAIDefense.BlocksWhenUnavailable() {
		return "fail-closed on AID unavailable: cisco_ai_defense.unavailable_action=block"
	}
	return "fail-open on AID unavailable: cisco_ai_defense.unavailable_action=allow"
}
