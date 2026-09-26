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
	"strings"
	"time"
)

// ManagedInspectionHealth is the managed_enterprise inspection state shown in
// /health and mapped onto the Secure Client availability. Available is false
// while Cisco AI Defense cannot be reached (no credential provider, no token,
// no inspector); UnavailableAction says whether those requests are currently
// being allowed or blocked: the configured cisco_ai_defense.unavailable_action,
// or block on a build with no managed-cloud support.
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
const managedInspectionUnwiredDetail = "no managed inspector is wired for agent hooks; check cisco_ai_defense.endpoint and managed-cloud enrollment, then reload the configuration"

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

// publishManagedInspectionHealth mirrors the managed inspection state into
// SidecarHealth, where /health and the Secure Client availability read it.
// Outside the Secure Client inspection profile it does nothing.
func (s *Sidecar) publishManagedInspectionHealth() {
	if s == nil || s.health == nil {
		return
	}
	cfg := s.currentConfig()
	if cfg == nil || !cfg.ManagedAIDOnly() {
		return
	}
	available, detail := s.managedInspectionState()
	s.health.SetManagedInspection(available, detail, managedAIDEffectiveUnavailableAction(cfg))
}

// refreshManagedInspectionHealth applies a reload: republish in
// managed_enterprise, otherwise drop the managed inspection state.
func (s *Sidecar) refreshManagedInspectionHealth(managedEnterprise bool) {
	if s == nil {
		return
	}
	if cfg := s.currentConfig(); managedEnterprise && cfg != nil && cfg.ManagedAIDOnly() {
		s.publishManagedInspectionHealth()
		return
	}
	s.managedHookInspector.Store(0)
	if s.health != nil {
		s.health.ClearManagedInspection()
	}
}

// probeManagedInspection re-checks an unavailable managed provider by
// minting a token, at most once per managedInspectionProbeInterval. Only a
// provider that was already built is probed; a provider that failed to
// build is left to the next reload, which also rebuilds the inspector. A
// failure reported by an inspection that had a token (AI Defense returned
// no verdict) is not probed: a token says nothing about whether AI Defense
// answers, so only the next real verdict clears it.
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
	s.setInspectionAvailability(err)
}
