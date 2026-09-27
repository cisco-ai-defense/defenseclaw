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
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
)

// ManagedInspectionHealth is the managed_enterprise inspection state shown in
// /health and mapped onto the Secure Client availability. Available is false
// while Cisco AI Defense cannot be reached (no credential provider, no token,
// no inspector); UnavailableAction says whether those requests are currently
// being allowed or blocked: block when cisco_ai_defense.unavailable_action is
// block (or the build has no managed-cloud support) and a connector the hook
// handlers evaluate is in action mode to enforce it, otherwise allow (see
// managedAIDUnavailablePosture).
type ManagedInspectionHealth struct {
	Available         bool      `json:"available"`
	Error             string    `json:"error,omitempty"`
	UnavailableAction string    `json:"unavailable_action"`
	Since             time.Time `json:"since"`
}

// SetManagedInspection records the managed inspection state. Subscribers are
// notified only when the state changes, because the managed inspector
// reports on every inspection.
func (h *SidecarHealth) SetManagedInspection(available bool, lastErr, unavailableAction string) {
	if h == nil {
		return
	}
	if available {
		lastErr = ""
	}
	unchanged := func() bool {
		current := h.managedInspection
		return current != nil &&
			current.Available == available &&
			current.Error == lastErr &&
			current.UnavailableAction == unavailableAction
	}
	// The common case is a repeat report from the per-inspection observer;
	// answer it under the read lock.
	h.mu.RLock()
	same := unchanged()
	h.mu.RUnlock()
	if same {
		return
	}
	h.mu.Lock()
	if unchanged() {
		h.mu.Unlock()
		return
	}
	h.managedInspection = &ManagedInspectionHealth{
		Available:         available,
		Error:             lastErr,
		UnavailableAction: unavailableAction,
		Since:             time.Now(),
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

// ClearManagedInspection drops the managed inspection state, for a reload
// that leaves managed_enterprise.
func (h *SidecarHealth) ClearManagedInspection() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.managedInspection == nil {
		h.mu.Unlock()
		return
	}
	h.managedInspection = nil
	h.mu.Unlock()
	h.notifySubscribers()
}

// Values of Sidecar.managedHookInspector.
const (
	managedHookInspectorWired   int32 = 1
	managedHookInspectorUnwired int32 = 2
)

// managedInspectionUnwiredDetail explains an unavailable inspection whose
// provider is healthy but whose hook lane never received an inspector.
const managedInspectionUnwiredDetail = "no managed inspector is wired for agent hooks; check cisco_ai_defense.endpoint and managed-cloud enrollment (the gateway retries every 30 seconds)"

const (
	// managedInspectionProbeInterval bounds how often an unavailable
	// provider is re-probed from the guardrail health ticker, so an idle
	// endpoint recovers without waiting for the next tool call.
	managedInspectionProbeInterval = 30 * time.Second
	managedInspectionProbeTimeout  = 5 * time.Second
)

// setManagedHookInspectorWired records whether the API server's hook lane
// holds a managed inspector and republishes the inspection state.
func (s *Sidecar) setManagedHookInspectorWired(wired bool) {
	if s == nil {
		return
	}
	state := managedHookInspectorUnwired
	if wired {
		state = managedHookInspectorWired
	}
	s.managedHookInspector.Store(state)
	s.publishManagedInspectionHealth()
}

// managedInspectionState combines the provider availability with the hook
// lane wiring: a healthy provider does not help when the hook lane has no
// inspector (for example an empty endpoint, or a provider that only became
// buildable after the API server started).
func (s *Sidecar) managedInspectionState() (bool, string) {
	available, detail := s.inspectionAvailability()
	if available && s.managedHookInspector.Load() == managedHookInspectorUnwired {
		return false, managedInspectionUnwiredDetail
	}
	return available, detail
}

// managedInspectionPublishTestHook, when set by a test, runs between a
// publisher's snapshot and its write into SidecarHealth. Production never
// sets it.
var managedInspectionPublishTestHook func()

// publishManagedInspectionHealth mirrors the managed inspection state into
// SidecarHealth, where /health and the Secure Client availability read it.
// Outside the Secure Client inspection profile it does nothing. Publishes are serialized and
// each one reads the state it writes, so the last publish always carries
// the latest state.
func (s *Sidecar) publishManagedInspectionHealth() {
	if s == nil || s.health == nil {
		return
	}
	s.managedInspectionPublishMu.Lock()
	defer s.managedInspectionPublishMu.Unlock()
	cfg := s.currentConfig()
	if cfg == nil || !cfg.ManagedAIDOnly() {
		return
	}
	available, detail := s.managedInspectionState()
	action := managedAIDUnavailablePosture(cfg, s.health)
	if hook := managedInspectionPublishTestHook; hook != nil {
		hook()
	}
	s.health.SetManagedInspection(available, detail, action)
}

// refreshManagedInspectionHealth applies a reload: republish in
// managed_enterprise, otherwise drop the managed inspection state. The
// clear takes the publish lock, so a publish that read the managed config
// before the reload finishes first and cannot write its snapshot after the
// clear; publishes that start later see the new config and do nothing.
func (s *Sidecar) refreshManagedInspectionHealth(managedEnterprise bool) {
	if s == nil {
		return
	}
	if cfg := s.currentConfig(); managedEnterprise && cfg != nil && cfg.ManagedAIDOnly() {
		s.publishManagedInspectionHealth()
		return
	}
	s.managedInspectionPublishMu.Lock()
	defer s.managedInspectionPublishMu.Unlock()
	s.managedHookInspector.Store(0)
	if s.health != nil {
		s.health.ClearManagedInspection()
	}
}

// retryManagedHookInspector wires a managed inspector onto the API server's
// hook lane when it was left without one: for example the provider build
// failed when the API server started and succeeded later for the guardrail,
// or failed on a condition that has since cleared. Without it the lane
// stays unwired until a reload changes cisco_ai_defense, and with
// unavailable_action=block every tool call that needs inspection is
// blocked. Runs on the guardrail health ticker, at most once per
// managedInspectionProbeInterval; an empty endpoint is left to the reload
// that sets one.
func (s *Sidecar) retryManagedHookInspector(ctx context.Context) {
	if s == nil || s.managedHookInspector.Load() != managedHookInspectorUnwired {
		return
	}
	cfg := s.currentConfig()
	if cfg == nil || !cfg.ManagedAIDOnly() || !cloudreg.Registered() ||
		strings.TrimSpace(cfg.CiscoAIDefense.Endpoint) == "" {
		return
	}
	// runAPI or a reload may be wiring right now; the next tick retries.
	if !s.hookInspectorMu.TryLock() {
		return
	}
	defer s.hookInspectorMu.Unlock()
	now := time.Now()
	if s.managedHookInspector.Load() != managedHookInspectorUnwired ||
		now.Sub(s.hookInspectorLastRetry) < managedInspectionProbeInterval {
		return
	}
	s.hookInspectorLastRetry = now
	api := s.apiSnapshot()
	if api == nil {
		return
	}
	inspector := s.newManagedInspector(ctx, "hook remote inspection still disabled")
	if inspector == nil {
		return
	}
	api.SetCiscoInspector(inspector)
	s.setManagedHookInspectorWired(true)
	fmt.Fprintln(os.Stderr, "[guardrail] managed_enterprise: hook-lane Cisco AI Defense inspector wired on retry")
}

// probeManagedInspection re-checks an unavailable managed provider by
// minting a token, at most once per managedInspectionProbeInterval. Only a
// provider that was already built is probed; a provider that failed to
// build is rebuilt by retryManagedHookInspector or the next reload. A
// failure reported by an inspection that had a token (AI Defense returned
// no verdict) is not probed: a token says nothing about whether AI Defense
// answers, so only the next real verdict clears it. The same holds for an
// outcome an inspection reports while the probe waits on its token: the
// probe then discards its result.
func (s *Sidecar) probeManagedInspection(ctx context.Context) {
	if s == nil {
		return
	}
	now := time.Now()
	s.inspectionMu.Lock()
	if s.inspectionAvailable || s.inspectionVerdictFailure ||
		now.Sub(s.inspectionLastProbe) < managedInspectionProbeInterval {
		s.inspectionMu.Unlock()
		return
	}
	s.inspectionLastProbe = now
	generation := s.inspectionGeneration
	s.inspectionMu.Unlock()

	s.cmidProviderMu.Lock()
	provider := s.cmidProviderInst
	s.cmidProviderMu.Unlock()
	if provider == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, managedInspectionProbeTimeout)
	defer cancel()
	token, err := provider.Token(probeCtx)
	if ctx.Err() != nil {
		return
	}
	if err == nil && strings.TrimSpace(token) == "" {
		err = errors.New("managed cloud token is empty")
	}
	s.inspectionMu.Lock()
	if s.inspectionGeneration != generation {
		// An inspection reported while the probe waited; its outcome is
		// newer than a token, and may be a no-verdict failure a token
		// must not clear.
		s.inspectionMu.Unlock()
		return
	}
	s.recordInspectionAvailabilityLocked(err)
	s.inspectionMu.Unlock()
	s.publishManagedInspectionHealth()
}
