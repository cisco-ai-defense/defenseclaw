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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
)

// A minted token does not make managed inspection available: a call that
// gets no verdict from AI Defense reports unavailable, a token-only probe
// does not clear it, and the next real verdict does.
func TestManagedInspectionFollowsTheVerdictNotTheToken(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow"}`)
	}))
	t.Cleanup(srv.Close)

	registerFakeCloudProvider(t, newFakeCloudProvider("token"), nil)
	s := managedInspectionSidecar(t)
	s.cfg.CiscoAIDefense.Endpoint = srv.URL
	inspector := s.newManagedInspector(context.Background(), "test")
	if inspector == nil {
		t.Fatal("newManagedInspector returned nil")
	}
	messages := []ChatMessage{{Role: "user", Content: "hello"}}

	if verdict := inspector.Inspect(context.Background(), messages); verdict != nil {
		t.Fatalf("inspect against a failing endpoint returned %+v", verdict)
	}
	got := s.health.Snapshot().ManagedInspection
	if got == nil || got.Available || !strings.Contains(got.Error, "no verdict") {
		t.Fatalf("after a failed inspection with a valid token: %+v", got)
	}

	s.inspectionMu.Lock()
	s.inspectionLastProbe = time.Now().Add(-2 * managedInspectionProbeInterval)
	s.inspectionMu.Unlock()
	s.probeManagedInspection(context.Background())
	if got := s.health.Snapshot().ManagedInspection; got == nil || got.Available {
		t.Fatalf("a token-only probe cleared a failed inspection: %+v", got)
	}

	failing.Store(false)
	if verdict := inspector.Inspect(context.Background(), messages); verdict == nil {
		t.Fatal("inspect against a recovered endpoint returned no verdict")
	}
	if got := s.health.Snapshot().ManagedInspection; got == nil || !got.Available {
		t.Fatalf("after a real verdict: %+v", got)
	}
}

// A managed build with no managed-cloud credential factory can never
// inspect, so the hook lane blocks requests that need inspection even
// under the default unavailable_action; requests with nothing to inspect
// and excluded hook surfaces stay allowed.
func TestHookManagedAIDUnsupportedBuildBlocksUninspectedRequests(t *testing.T) {
	req := &ToolInspectRequest{Tool: "run_shell", Args: json.RawMessage(`{"command":"echo dc-marker"}`)}
	a := managedHookServer(nil)
	if v := a.inspectToolPolicy(req); v == nil || v.Action != "allow" {
		t.Fatalf("supported build, default posture: %+v, want allow", v)
	}
	a.SetManagedInspectionUnsupported(true)
	v := a.inspectToolPolicy(req)
	if v == nil || v.Action != "block" || v.Reason != managedAIDUnsupportedReason {
		t.Fatalf("unsupported build: %+v, want the unsupported block", v)
	}
	if v := a.inspectManagedAIDOnly(context.Background(), "run_shell", ""); v == nil || v.Action != "allow" {
		t.Fatalf("nothing to inspect on an unsupported build: %+v, want allow", v)
	}
	a.scannerCfg.CiscoAIDefense.ScanHookSurface = boolPtr(false)
	if v := a.inspectToolPolicy(req); v == nil || v.Action != "allow" {
		t.Fatalf("excluded hook surface on an unsupported build: %+v, want allow", v)
	}
}

func TestManagedInspectionUnsupportedFollowsTheCredentialFactory(t *testing.T) {
	managedCfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cloudreg.Register(nil)
	t.Cleanup(func() { cloudreg.Register(nil) })
	if !managedInspectionUnsupported(managedCfg) {
		t.Fatal("a managed config on a build with no factory is not reported unsupported")
	}
	if got := managedAIDEffectiveUnavailableAction(managedCfg); got != config.AIDUnavailableActionBlock {
		t.Fatalf("effective action without a factory = %q, want block", got)
	}
	if managedInspectionUnsupported(&config.Config{}) {
		t.Fatal("a non-managed config is reported unsupported")
	}

	registerFakeCloudProvider(t, newFakeCloudProvider("token"), nil)
	if managedInspectionUnsupported(managedCfg) {
		t.Fatal("a build with a factory is reported unsupported")
	}
	if got := managedAIDEffectiveUnavailableAction(managedCfg); got != config.AIDUnavailableActionAllow {
		t.Fatalf("effective default action with a factory = %q, want allow", got)
	}
	managedCfg.CiscoAIDefense.UnavailableAction = config.AIDUnavailableActionBlock
	if got := managedAIDEffectiveUnavailableAction(managedCfg); got != config.AIDUnavailableActionBlock {
		t.Fatalf("effective configured action = %q, want block", got)
	}
}
