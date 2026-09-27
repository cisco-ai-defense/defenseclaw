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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

	s.cfg.Guardrail.Mode = "action"
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

// blockingCloudProvider holds Token until released, so a test can land an
// inspection outcome while a probe waits on its token.
type blockingCloudProvider struct {
	entered chan struct{}
	release chan struct{}
}

func (p *blockingCloudProvider) Token(context.Context) (string, error) {
	close(p.entered)
	<-p.release
	return "token", nil
}

func (p *blockingCloudProvider) Refresh(context.Context) error { return nil }
func (p *blockingCloudProvider) Invalidate()                   {}

// A no-verdict failure an inspection reports while the probe waits on a
// token is newer than the probe's result; the token must not clear it.
func TestProbeManagedInspectionKeepsANewerNoVerdictFailure(t *testing.T) {
	s := managedInspectionSidecar(t)
	provider := &blockingCloudProvider{entered: make(chan struct{}), release: make(chan struct{})}
	s.cmidProviderInst = provider
	s.setInspectionAvailability(errors.New("cmid daemon not running"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.probeManagedInspection(context.Background())
	}()
	select {
	case <-provider.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not ask for a token")
	}
	s.setInspectionAvailability(errManagedAIDNoVerdict)
	close(provider.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not finish")
	}

	got := s.health.Snapshot().ManagedInspection
	if got == nil || got.Available || got.Error != errManagedAIDNoVerdict.Error() {
		t.Fatalf("probe overwrote a newer no-verdict failure: %+v", got)
	}
	s.inspectionMu.RLock()
	verdictFailure := s.inspectionVerdictFailure
	s.inspectionMu.RUnlock()
	if !verdictFailure {
		t.Fatal("probe cleared the no-verdict flag, so later probes would clear the failure too")
	}
}

// Publishes are serialized: a publisher that took its snapshot before a
// newer outcome cannot write that older snapshot last.
func TestPublishManagedInspectionHealthCannotWriteAnOlderSnapshotLast(t *testing.T) {
	s := managedInspectionSidecar(t)
	s.setInspectionAvailability(nil)

	paused := make(chan struct{})
	resume := make(chan struct{})
	var first atomic.Bool
	managedInspectionPublishTestHook = func() {
		if first.CompareAndSwap(false, true) {
			close(paused)
			<-resume
		}
	}
	t.Cleanup(func() { managedInspectionPublishTestHook = nil })

	staleDone := make(chan struct{})
	go func() {
		defer close(staleDone)
		s.publishManagedInspectionHealth() // snapshots "available"
	}()
	select {
	case <-paused:
	case <-time.After(5 * time.Second):
		t.Fatal("stale publisher did not reach its write")
	}

	newerDone := make(chan struct{})
	go func() {
		defer close(newerDone)
		s.setInspectionAvailability(errManagedAIDNoVerdict)
	}()
	// Without serialization the newer publish completes here; with it,
	// it waits for the stale publisher.
	select {
	case <-newerDone:
	case <-time.After(500 * time.Millisecond):
	}
	close(resume)
	for _, ch := range []chan struct{}{staleDone, newerDone} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("publisher did not finish")
		}
	}

	if got := s.health.Snapshot().ManagedInspection; got == nil || got.Available ||
		got.Error != errManagedAIDNoVerdict.Error() {
		t.Fatalf("an older snapshot was written last: %+v", got)
	}
}

// A hook lane left without an inspector because the provider build failed
// when the API server started is rewired from the guardrail health ticker
// once the build succeeds, so unavailable_action=block stops blocking every
// tool call. Retries are rate limited.
func TestManagedHealthTickerRewiresAnUnwiredHookLane(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow"}`)
	}))
	t.Cleanup(srv.Close)

	var buildable atomic.Bool
	var builds atomic.Int32
	cloudreg.Register(func(cloudreg.Config) (cloudreg.Provider, error) {
		builds.Add(1)
		if !buildable.Load() {
			return nil, errors.New("managed cloud auth library not trusted yet")
		}
		return newFakeCloudProvider("token"), nil
	})
	t.Cleanup(func() { cloudreg.Register(nil) })

	s := managedInspectionSidecar(t)
	s.cfg.CiscoAIDefense.Endpoint = srv.URL
	api := managedBlockingHookServer(nil)
	s.apiServer = api
	req := &ToolInspectRequest{Tool: "run_shell", Args: json.RawMessage(`{"command":"ls -la"}`)}

	// runAPI's wiring with a provider that cannot be built yet.
	if inspector := s.pickInspector(context.Background()); inspector != nil {
		t.Fatalf("pickInspector with a failing build returned %T", inspector)
	}
	s.setManagedHookInspectorWired(false)
	v := api.inspectToolPolicy(req)
	if v == nil {
		t.Fatal("unwired hook lane returned no verdict")
	}
	assertManagedAIDUnavailableBlock(t, v.Action, v.Severity, v.Reason, v.Findings)

	// Still failing: one retry, then rate limited.
	before := builds.Load()
	s.addManagedInspectionHealth(context.Background(), map[string]interface{}{})
	s.addManagedInspectionHealth(context.Background(), map[string]interface{}{})
	if got := builds.Load() - before; got != 1 {
		t.Fatalf("provider builds during two ticks = %d, want 1", got)
	}
	if api.currentCiscoInspector() != nil {
		t.Fatal("a failed retry wired an inspector")
	}

	buildable.Store(true)
	s.hookInspectorMu.Lock()
	s.hookInspectorLastRetry = time.Now().Add(-managedInspectionProbeInterval)
	s.hookInspectorMu.Unlock()
	detail := map[string]interface{}{}
	s.addManagedInspectionHealth(context.Background(), detail)
	if api.currentCiscoInspector() == nil || s.managedHookInspector.Load() != managedHookInspectorWired {
		t.Fatal("the health ticker did not rewire the hook lane after the provider became buildable")
	}
	if v := api.inspectToolPolicy(req); v == nil || v.Action != "allow" {
		t.Fatalf("rewired hook lane verdict = %+v, want the AI Defense allow", v)
	}
	if got := s.health.Snapshot().ManagedInspection; got == nil || !got.Available {
		t.Fatalf("after the rewired lane got a verdict: %+v", got)
	}
}

// The single-connector proxy boot has no guardrail health ticker, so in
// managed_enterprise it runs the managed inspection upkeep beside the proxy:
// a hook lane left unwired when the API server started (OpenClaw sends its
// tool calls there) is rewired once the provider builds, instead of blocking
// every tool call under unavailable_action=block until a reload.
func TestManagedProxyBootRewiresAnUnwiredHookLane(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow"}`)
	}))
	t.Cleanup(srv.Close)

	var buildable atomic.Bool
	setCMIDDirectLaneRefused(t, false)
	cloudreg.Register(func(cloudreg.Config) (cloudreg.Provider, error) {
		if !buildable.Load() {
			return nil, errors.New("managed cloud auth library not trusted yet")
		}
		return newFakeCloudProvider("token"), nil
	})
	t.Cleanup(func() { cloudreg.Register(nil) })

	s := managedInspectionSidecar(t)
	s.cfg.CiscoAIDefense.Endpoint = srv.URL
	api := managedBlockingHookServer(nil)
	s.apiServer = api
	req := &ToolInspectRequest{Tool: "run_shell", Args: json.RawMessage(`{"command":"ls -la"}`)}

	// runAPI's wiring with a provider that cannot be built yet.
	if inspector := s.pickInspector(context.Background()); inspector != nil {
		t.Fatalf("pickInspector with a failing build returned %T", inspector)
	}
	s.setManagedHookInspectorWired(false)
	v := api.inspectToolPolicy(req)
	if v == nil {
		t.Fatal("unwired hook lane returned no verdict")
	}
	assertManagedAIDUnavailableBlock(t, v.Action, v.Severity, v.Reason, v.Findings)

	buildable.Store(true)
	// A disabled proxy parks until ctx ends, which is all this test needs
	// from it.
	proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{}, health: s.health}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.runGuardrailProxy(ctx, proxy) }()
	for deadline := time.Now().Add(5 * time.Second); api.currentCiscoInspector() == nil && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("proxy boot: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy boot did not stop with its context")
	}
	if api.currentCiscoInspector() == nil || s.managedHookInspector.Load() != managedHookInspectorWired {
		t.Fatal("the managed proxy boot did not rewire the hook lane after the provider became buildable")
	}
	if v := api.inspectToolPolicy(req); v == nil || v.Action != "allow" {
		t.Fatalf("rewired hook lane verdict = %+v, want the AI Defense allow", v)
	}
	if got := s.health.Snapshot().ManagedInspection; got == nil || !got.Available {
		t.Fatalf("after the rewired lane got a verdict: %+v", got)
	}
}

// A reload that leaves managed_enterprise clears the managed inspection
// state after any publish that read the managed config before the reload.
// Nothing publishes outside managed_enterprise, so a snapshot that publish
// wrote after the clear would stay, and the Secure Client availability would
// keep reporting DEGRADED.
func TestRefreshManagedInspectionHealthClearsAfterAnInFlightPublish(t *testing.T) {
	s := managedInspectionSidecar(t)
	s.setInspectionAvailability(errors.New("managed cloud token unavailable"))

	paused := make(chan struct{})
	resume := make(chan struct{})
	var first atomic.Bool
	managedInspectionPublishTestHook = func() {
		if first.CompareAndSwap(false, true) {
			close(paused)
			<-resume
		}
	}
	t.Cleanup(func() { managedInspectionPublishTestHook = nil })

	staleDone := make(chan struct{})
	go func() {
		defer close(staleDone)
		s.publishManagedInspectionHealth() // reads the managed config
	}()
	select {
	case <-paused:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not reach its write")
	}

	// The reload publishes a config outside managed_enterprise, then clears.
	s.cfgCurrent.Store(&config.Config{
		DataDir:        s.cfg.DataDir,
		DeploymentMode: string(config.DeploymentModeUnmanagedBYOD),
		Guardrail:      config.GuardrailConfig{Enabled: true},
	})
	clearDone := make(chan struct{})
	go func() {
		defer close(clearDone)
		s.refreshManagedInspectionHealth(false)
	}()
	// Without the publish lock the clear completes here, before the
	// publisher writes.
	select {
	case <-clearDone:
	case <-time.After(500 * time.Millisecond):
	}
	close(resume)
	for _, ch := range []chan struct{}{staleDone, clearDone} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("publish or clear did not finish")
		}
	}

	if got := s.health.Snapshot().ManagedInspection; got != nil {
		t.Fatalf("managed inspection state left after leaving managed_enterprise: %+v", got)
	}
}

// The hook-lane retry rebuilds a failing provider every
// managedInspectionProbeInterval. A build that keeps failing the same way
// is logged and recorded as a failed inspection once, not on every retry
// with no request behind it; a new cause is reported again.
func TestManagedHookInspectorRetryReportsARepeatedBuildFailureOnce(t *testing.T) {
	var cause atomic.Value
	cause.Store("managed cloud auth library not trusted yet")
	cloudreg.Register(func(cloudreg.Config) (cloudreg.Provider, error) {
		return nil, errors.New(cause.Load().(string))
	})
	t.Cleanup(func() { cloudreg.Register(nil) })

	s := managedInspectionSidecar(t)
	s.cfg.CiscoAIDefense.Endpoint = "https://aid.example.invalid"
	s.apiServer = managedBlockingHookServer(nil)
	retry := func() {
		// Run as if the retry interval and the build log cooldown
		// had both elapsed.
		s.hookInspectorMu.Lock()
		s.hookInspectorLastRetry = time.Time{}
		s.hookInspectorMu.Unlock()
		s.cmidProviderMu.Lock()
		s.cmidBuildLastLog = time.Time{}
		s.cmidProviderMu.Unlock()
		s.retryManagedHookInspector(context.Background())
	}
	lines := func(out string) (build, inspect int) {
		return strings.Count(out, "CMID provider build failed"), strings.Count(out, "[gateway] error ")
	}

	var wired Inspector
	out := captureStderr(t, func() {
		// runAPI's wiring reports the failure.
		wired = s.pickInspector(context.Background())
		s.setManagedHookInspectorWired(wired != nil)
		retry()
		retry()
	})
	if wired != nil {
		t.Fatalf("pickInspector with a failing build returned %T", wired)
	}
	if build, inspect := lines(out); build != 1 || inspect != 1 {
		t.Fatalf("startup and two retries with one cause: %d build and %d error lines, want 1 and 1:\n%s", build, inspect, out)
	}

	cause.Store("managed cloud auth library missing")
	out = captureStderr(t, func() {
		retry()
		retry()
	})
	if build, inspect := lines(out); build != 1 || inspect != 1 {
		t.Fatalf("two retries with a new cause: %d build and %d error lines, want 1 and 1:\n%s", build, inspect, out)
	}
	if s.managedHookInspector.Load() != managedHookInspectorUnwired {
		t.Fatal("a failed retry marked the hook lane wired")
	}
}
