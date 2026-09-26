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
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
)

func TestSidecarHealthManagedInspectionSnapshotAndDedup(t *testing.T) {
	h := NewSidecarHealth()
	if snap := h.Snapshot(); snap.ManagedInspection != nil {
		t.Fatalf("managed inspection present before any report: %+v", snap.ManagedInspection)
	}
	notify, cancel := h.Subscribe()
	defer cancel()

	h.SetManagedInspection(false, "managed cloud token unavailable", config.AIDUnavailableActionAllow)
	select {
	case <-notify:
	case <-time.After(time.Second):
		t.Fatal("first report did not notify subscribers")
	}
	h.SetManagedInspection(false, "managed cloud token unavailable", config.AIDUnavailableActionAllow)
	select {
	case <-notify:
		t.Fatal("an unchanged report notified subscribers")
	default:
	}

	snap := h.Snapshot()
	if snap.ManagedInspection == nil || snap.ManagedInspection.Available ||
		snap.ManagedInspection.Error != "managed cloud token unavailable" ||
		snap.ManagedInspection.UnavailableAction != config.AIDUnavailableActionAllow {
		t.Fatalf("snapshot = %+v", snap.ManagedInspection)
	}
	snap.ManagedInspection.Available = true
	if h.Snapshot().ManagedInspection.Available {
		t.Fatal("snapshot aliases the stored managed inspection state")
	}
	raw, err := json.Marshal(h.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	block, ok := decoded["managed_inspection"].(map[string]any)
	if !ok || block["available"] != false || block["unavailable_action"] != "allow" {
		t.Fatalf("/health managed_inspection = %v", decoded["managed_inspection"])
	}

	h.SetManagedInspection(true, "ignored when available", config.AIDUnavailableActionBlock)
	if got := h.Snapshot().ManagedInspection; !got.Available || got.Error != "" {
		t.Fatalf("recovered snapshot = %+v", got)
	}
	h.ClearManagedInspection()
	if got := h.Snapshot().ManagedInspection; got != nil {
		t.Fatalf("cleared snapshot = %+v", got)
	}
}

func TestSetInspectionAvailabilityPublishesOnlyInManagedMode(t *testing.T) {
	s := managedInspectionSidecar(t)
	s.setInspectionAvailability(errors.New("managed cloud token unavailable"))
	got := s.health.Snapshot().ManagedInspection
	if got == nil || got.Available || got.Error != "managed cloud token unavailable" {
		t.Fatalf("managed snapshot = %+v", got)
	}

	s.cfg.CiscoAIDefense.UnavailableAction = config.AIDUnavailableActionBlock
	s.refreshManagedInspectionHealth(true)
	if got := s.health.Snapshot().ManagedInspection; got.UnavailableAction != config.AIDUnavailableActionBlock {
		t.Fatalf("reload did not republish the unavailable action: %+v", got)
	}

	s.refreshManagedInspectionHealth(false)
	if got := s.health.Snapshot().ManagedInspection; got != nil {
		t.Fatalf("leaving managed_enterprise left %+v", got)
	}

	open := &Sidecar{cfg: &config.Config{DataDir: t.TempDir()}, health: NewSidecarHealth()}
	open.setInspectionAvailability(errors.New("unused"))
	if got := open.health.Snapshot().ManagedInspection; got != nil {
		t.Fatalf("opensource sidecar published managed inspection %+v", got)
	}
}

// A healthy provider is not enough: if the hook lane never received an
// inspector, managed hooks are still failing open.
func TestManagedInspectionStateAccountsForTheHookLane(t *testing.T) {
	s := managedInspectionSidecar(t)
	s.setInspectionAvailability(nil)
	if got := s.health.Snapshot().ManagedInspection; got == nil || !got.Available {
		t.Fatalf("provider healthy, wiring unknown: %+v", got)
	}
	s.setManagedHookInspectorWired(false)
	got := s.health.Snapshot().ManagedInspection
	if got == nil || got.Available || got.Error != managedInspectionUnwiredDetail {
		t.Fatalf("provider healthy, hook lane unwired: %+v", got)
	}
	detail := map[string]interface{}{}
	s.addManagedInspectionHealth(context.Background(), detail)
	if detail["inspection_available"] != false || detail["inspection_error"] != managedInspectionUnwiredDetail {
		t.Fatalf("guardrail details disagree with the managed inspection state: %v", detail)
	}
	s.setManagedHookInspectorWired(true)
	if got := s.health.Snapshot().ManagedInspection; !got.Available {
		t.Fatalf("provider healthy, hook lane wired: %+v", got)
	}
}

// The managed inspector reports every token outcome; a failure after boot
// must reach the snapshot the Secure Client availability is mapped from.
func TestManagedInspectorTokenFailureReachesHealthSnapshot(t *testing.T) {
	provider := newFakeCloudProvider("token")
	registerFakeCloudProvider(t, provider, nil)
	s := managedInspectionSidecar(t)
	s.cfg.CiscoAIDefense.Endpoint = "https://aidefense.example.test"

	inspector := s.newManagedInspector(context.Background(), "test")
	if inspector == nil {
		t.Fatal("newManagedInspector returned nil")
	}
	if got := s.health.Snapshot().ManagedInspection; got == nil || !got.Available {
		t.Fatalf("after a successful build: %+v", got)
	}

	provider.Invalidate() // exhaust the only token
	s.cmidProviderMu.Lock()
	s.cmidProviderInst.Invalidate() // drop the cached token as well
	s.cmidProviderMu.Unlock()
	if verdict := inspector.Inspect(context.Background(), []ChatMessage{{Role: "user", Content: "hello"}}); verdict != nil {
		t.Fatalf("inspect without a token returned %+v", verdict)
	}
	if got := s.health.Snapshot().ManagedInspection; got == nil || got.Available {
		t.Fatalf("after a token failure: %+v", got)
	}
}

type countingCloudProvider struct {
	calls int
	err   error
}

func (p *countingCloudProvider) Token(context.Context) (string, error) {
	p.calls++
	if p.err != nil {
		return "", p.err
	}
	return "token", nil
}

func (p *countingCloudProvider) Refresh(context.Context) error { return nil }
func (p *countingCloudProvider) Invalidate()                   {}

// An idle endpoint whose provider recovers after boot must not stay
// DEGRADED until the next tool call.
func TestProbeManagedInspectionRecoversARateLimitedProvider(t *testing.T) {
	s := managedInspectionSidecar(t)
	provider := &countingCloudProvider{err: errors.New("cmid daemon not running")}
	s.cmidProviderInst = provider
	s.setInspectionAvailability(errors.New("cmid daemon not running"))

	s.probeManagedInspection(context.Background())
	if provider.calls != 1 {
		t.Fatalf("probe calls = %d, want 1", provider.calls)
	}
	s.probeManagedInspection(context.Background())
	if provider.calls != 1 {
		t.Fatalf("probe was not rate limited: %d calls", provider.calls)
	}
	if got := s.health.Snapshot().ManagedInspection; got.Available {
		t.Fatalf("failed probe reported available: %+v", got)
	}

	provider.err = nil
	s.inspectionMu.Lock()
	s.inspectionLastProbe = time.Now().Add(-managedInspectionProbeInterval)
	s.inspectionMu.Unlock()
	s.probeManagedInspection(context.Background())
	if got := s.health.Snapshot().ManagedInspection; got == nil || !got.Available {
		t.Fatalf("recovered probe: %+v", got)
	}
	s.probeManagedInspection(context.Background())
	if provider.calls != 2 {
		t.Fatalf("an available provider was probed again: %d calls", provider.calls)
	}

	// No provider built: nothing to probe.
	empty := managedInspectionSidecar(t)
	empty.setInspectionAvailability(cloudreg.ErrNoProviderRegistered)
	empty.probeManagedInspection(context.Background())
	if got := empty.health.Snapshot().ManagedInspection; got.Available {
		t.Fatalf("probe without a provider reported available: %+v", got)
	}
}
