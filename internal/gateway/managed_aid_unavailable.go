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
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
)

// managed_enterprise disables every local detector, so Cisco AI Defense is
// the only decision-maker. cisco_ai_defense.unavailable_action lets an
// administrator choose what happens when AI Defense should have inspected a
// request but could not: "allow" (the default) keeps the historical
// fail-open posture, "block" returns a block verdict instead. The helpers
// below are the single place both lanes (hook and proxy) consult.

const (
	// managedAIDUnavailableReason is the verdict reason for a request blocked
	// because AI Defense could not inspect it. It names the setting so an
	// operator reading the audit log knows how to change the posture.
	managedAIDUnavailableReason = "Cisco AI Defense could not inspect this request; blocked by cisco_ai_defense.unavailable_action=block"
	// managedAIDUnavailableFinding tags the block in findings so dashboards
	// can separate it from a policy match returned by AI Defense.
	managedAIDUnavailableFinding = "ai-defense:unavailable"
)

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
	cfg := a.managedAIDPolicyConfig()
	if cfg == nil || !cfg.CiscoAIDefense.BlocksWhenUnavailable() {
		return nil
	}
	logManagedAIDUnavailableBlock("hook", reason)
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
	logManagedAIDUnavailableBlock("proxy/"+normalizeManagedAIDFailOpenDirection(direction), reason)
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
// blocked because AI Defense could not inspect it. It shares the skip log's
// cooldown clock under a distinct key.
func logManagedAIDUnavailableBlock(lane, reason string) {
	key := "unavailable-block:" + lane + ":" + reason
	now := time.Now()
	managedAIDSkipState.mu.Lock()
	if now.Sub(managedAIDSkipState.last[key]) < managedAIDSkipCooldown {
		managedAIDSkipState.mu.Unlock()
		return
	}
	managedAIDSkipState.last[key] = now
	managedAIDSkipState.mu.Unlock()
	fmt.Fprintf(defaultLogWriter,
		"  [cisco-ai-defense] WARNING: managed_enterprise AID inspection unavailable (lane=%s reason=%s) — request BLOCKED by cisco_ai_defense.unavailable_action=block\n",
		lane, normalizeManagedAIDFailOpenReason(reason))
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
// the configured unavailable action, and, while it cannot, the cause and a
// hint that says what happens to tool calls. It runs on the guardrail
// health ticker, so it also re-probes an unavailable provider and refreshes
// the Secure Client availability.
func (s *Sidecar) addManagedInspectionHealth(ctx context.Context, detail map[string]interface{}) {
	if s == nil || detail == nil {
		return
	}
	s.probeManagedInspection(ctx)
	s.publishManagedInspectionHealth()
	available, cause := s.managedInspectionState()
	action := config.AIDUnavailableActionAllow
	if cfg := s.currentConfig(); cfg != nil {
		action = cfg.CiscoAIDefense.EffectiveUnavailableAction()
	}
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
