// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/routing"
)

type channelModelRouterHealthChecker struct {
	results   chan bool
	completed chan bool
}

func (c *channelModelRouterHealthChecker) Healthy(ctx context.Context) bool {
	select {
	case result := <-c.results:
		c.completed <- result
		return result
	case <-ctx.Done():
		return false
	}
}

type blockingModelRouterHealthChecker struct {
	started chan struct{}
	once    sync.Once
}

func (c *blockingModelRouterHealthChecker) Healthy(ctx context.Context) bool {
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	return false
}

func waitForRoutingState(t *testing.T, health *SidecarHealth, want SubsystemState) SubsystemHealth {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		snapshot := health.Snapshot().Routing
		if snapshot.State == want {
			return snapshot
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("routing state did not become %q; got %q", want, health.Snapshot().Routing.State)
	return SubsystemHealth{}
}

func waitForRoutingHealthV8Rows(t *testing.T, database *sql.DB, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var count int
		err := database.QueryRow(`SELECT COUNT(*) FROM audit_events
			WHERE event_name IN ('subsystem.degraded', 'subsystem.restored')`).Scan(&count)
		if err == nil && count >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	var count int
	_ = database.QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE event_name IN ('subsystem.degraded', 'subsystem.restored')`).Scan(&count)
	t.Fatalf("routing v8 health rows = %d, want at least %d", count, want)
}

func TestEffectiveRoutingHealthDetailsPublishesRuntimeValues(t *testing.T) {
	tests := []struct {
		name        string
		cfg         config.RoutingConfig
		wantMode    string
		wantVersion string
		wantPort    int
		hasPort     bool
	}{
		{
			name:        "managed defaults",
			cfg:         config.RoutingConfig{Enabled: true},
			wantMode:    "managed",
			wantVersion: routing.TestedVersion,
			wantPort:    routing.DefaultAPIPort,
			hasPort:     true,
		},
		{
			name: "managed explicit values",
			cfg: config.RoutingConfig{
				Enabled: true,
				Version: "v" + routing.TestedVersion,
				Port:    9080,
			},
			wantMode:    "managed",
			wantVersion: routing.TestedVersion,
			wantPort:    9080,
			hasPort:     true,
		},
		{
			name: "remote endpoint",
			cfg: config.RoutingConfig{
				Enabled: true,
				Remote:  config.RoutingRemoteConfig{Endpoint: "http://router.internal:8080"},
			},
			wantMode:    "remote",
			wantVersion: routing.TestedVersion,
			hasPort:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details := effectiveRoutingHealthDetails(tt.cfg)
			if got := details["mode"]; got != tt.wantMode {
				t.Fatalf("mode = %v, want %q", got, tt.wantMode)
			}
			if got := details["version"]; got != tt.wantVersion {
				t.Fatalf("version = %v, want %q", got, tt.wantVersion)
			}
			gotPort, hasPort := details["port"]
			if hasPort != tt.hasPort {
				t.Fatalf("port presence = %v, want %v", hasPort, tt.hasPort)
			}
			if tt.hasPort && gotPort != tt.wantPort {
				t.Fatalf("port = %v, want %d", gotPort, tt.wantPort)
			}
		})
	}
}

func TestRunModelRouterHealthMonitorPublishesFailureAndRecovery(t *testing.T) {
	health := NewSidecarHealth()
	details := map[string]interface{}{
		"enabled": true,
		"mode":    "managed",
		"port":    routing.DefaultAPIPort,
	}
	health.SetRouting(StateRunning, "", details)
	sidecar := &Sidecar{health: health}
	checker := &channelModelRouterHealthChecker{
		results:   make(chan bool, 3),
		completed: make(chan bool, 3),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sidecar.runModelRouterHealthMonitor(ctx, checker, details, time.Millisecond, 100*time.Millisecond)
	}()

	checker.results <- false
	<-checker.completed
	failed := waitForRoutingState(t, health, StateError)
	if failed.LastError != modelRouterHealthProbeError {
		t.Fatalf("failure last_error = %q, want %q", failed.LastError, modelRouterHealthProbeError)
	}

	checker.results <- false
	<-checker.completed
	if got := health.Snapshot().Routing.Since; !got.Equal(failed.Since) {
		t.Fatalf("repeated failure changed transition time: got %v, want %v", got, failed.Since)
	}

	checker.results <- true
	<-checker.completed
	recovered := waitForRoutingState(t, health, StateRunning)
	if recovered.LastError != "" {
		t.Fatalf("recovery retained last_error %q", recovered.LastError)
	}
	if recovered.Details["port"] != routing.DefaultAPIPort {
		t.Fatalf("recovery details port = %v, want %d", recovered.Details["port"], routing.DefaultAPIPort)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("router health monitor did not stop after cancellation")
	}
}

func TestRunModelRouterHealthMonitorBoundsProbe(t *testing.T) {
	health := NewSidecarHealth()
	health.SetRouting(StateRunning, "", nil)
	sidecar := &Sidecar{health: health}
	checker := &blockingModelRouterHealthChecker{started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sidecar.runModelRouterHealthMonitor(ctx, checker, nil, time.Millisecond, 10*time.Millisecond)
	}()

	select {
	case <-checker.started:
	case <-time.After(time.Second):
		t.Fatal("router health probe did not start")
	}
	failed := waitForRoutingState(t, health, StateError)
	if failed.LastError != modelRouterHealthProbeError {
		t.Fatalf("bounded probe last_error = %q, want %q", failed.LastError, modelRouterHealthProbeError)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("router health monitor did not stop after cancellation")
	}
}

func TestRunModelRouterHealthMonitorCancellationInterruptsProbe(t *testing.T) {
	health := NewSidecarHealth()
	health.SetRouting(StateRunning, "", nil)
	sidecar := &Sidecar{health: health}
	checker := &blockingModelRouterHealthChecker{started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sidecar.runModelRouterHealthMonitor(ctx, checker, nil, time.Millisecond, time.Hour)
	}()

	select {
	case <-checker.started:
	case <-time.After(time.Second):
		t.Fatal("router health probe did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("router health monitor did not stop its in-flight probe after cancellation")
	}
	if got := health.Snapshot().Routing.State; got != StateRunning {
		t.Fatalf("cancellation published a spurious routing failure: got %q", got)
	}
}

func TestRunModelRouterHealthMonitorPublishesGenerationSafeV8Transitions(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	health := NewSidecarHealth()
	sidecar := &Sidecar{health: health}
	if err := sidecar.bindObservabilityRuntime(runtime); err != nil {
		t.Fatal(err)
	}

	const promptCanary = "PRIVATE-PROMPT-CANARY-routing-health"
	const modelCanary = "private-model-alias-routing-health"
	details := effectiveRoutingHealthDetails(config.RoutingConfig{
		Enabled: true,
		Models: []config.RoutingModelBackend{{
			Name: modelCanary, Provider: "private-provider", Model: modelCanary,
		}},
	})
	// The monitor owns only health state. Even if a future caller adds a
	// content-bearing detail, canonical v8 routing health must ignore it.
	details["test_prompt_canary"] = promptCanary
	health.SetRouting(StateRunning, "", details)

	database, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	initialGeneration := runtime.Active().Generation()
	initialDigest := runtime.Active().Digest()

	checker := &channelModelRouterHealthChecker{
		results:   make(chan bool, 2),
		completed: make(chan bool, 2),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sidecar.runModelRouterHealthMonitor(ctx, checker, details, time.Millisecond, 100*time.Millisecond)
	}()

	checker.results <- false
	<-checker.completed
	waitForRoutingState(t, health, StateError)
	waitForRoutingHealthV8Rows(t, database, 1)

	disabled := false
	retentionDays := 0
	storePath := capture.store.DatabasePath()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            storePath,
			JudgeBodiesPath: filepath.Join(filepath.Dir(storePath), "judge-bodies.db"),
			RetentionDays:   &retentionDays,
		},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketPlatformHealth: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reload, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false))
	if reloadErr != nil || reload.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload status=%s err=%v", reload.Status(), reloadErr)
	}

	checker.results <- true
	<-checker.completed
	waitForRoutingState(t, health, StateRunning)
	waitForRoutingHealthV8Rows(t, database, 2)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("router health monitor did not stop after v8 transition test")
	}

	rows, err := database.Query(`SELECT event_name, mandatory, projected_record_json FROM audit_events
		WHERE event_name IN ('subsystem.degraded', 'subsystem.restored') ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type routingHealthRecord struct {
		eventName  string
		mandatory  int
		projected  string
		body       map[string]interface{}
		provenance observability.Provenance
	}
	var records []routingHealthRecord
	for rows.Next() {
		var record routingHealthRecord
		if err := rows.Scan(&record.eventName, &record.mandatory, &record.projected); err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Body       map[string]interface{}   `json:"body"`
			Provenance observability.Provenance `json:"provenance"`
		}
		if err := json.Unmarshal([]byte(record.projected), &decoded); err != nil {
			t.Fatal(err)
		}
		record.body = decoded.Body
		record.provenance = decoded.Provenance
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("routing v8 transition rows=%d, want 2", len(records))
	}
	if records[0].eventName != observability.TelemetryEventSubsystemDegraded ||
		records[0].body["defenseclaw.health.subsystem"] != routingHealthV8Subsystem ||
		records[0].body["defenseclaw.health.state"] != "degraded" ||
		records[0].body["defenseclaw.schema.error_code"] != routingHealthV8ProbeErrorCode ||
		records[0].mandatory != 1 ||
		records[0].provenance.ConfigGeneration != int64(initialGeneration) ||
		records[0].provenance.ConfigDigest != initialDigest {
		t.Fatalf("degraded routing health record=%+v", records[0])
	}
	if records[1].eventName != observability.TelemetryEventSubsystemRestored ||
		records[1].body["floor_only"] != true ||
		records[1].body["detail_state"] != "omitted" ||
		len(records[1].body) != 2 ||
		records[1].mandatory != 1 ||
		records[1].provenance.ConfigGeneration != int64(reload.ActiveGraph().Generation()) ||
		records[1].provenance.ConfigDigest != reload.ActiveGraph().Digest() {
		t.Fatalf("restored routing health record=%+v", records[1])
	}
	projected := records[0].projected + records[1].projected
	for _, canary := range []string{promptCanary, modelCanary, "private-provider"} {
		if strings.Contains(projected, canary) {
			t.Fatalf("routing health v8 projection leaked %q: %s", canary, projected)
		}
	}

	gatewayErrors := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawGatewayErrors,
	)
	if len(gatewayErrors) != 1 ||
		gatewayErrors[0].Attributes()["defenseclaw.metric.error.subsystem"] != routingHealthV8Subsystem ||
		gatewayErrors[0].Attributes()["defenseclaw.metric.error.code"] != routingHealthV8ProbeErrorCode {
		t.Fatalf("routing gateway error metrics=%v", gatewayErrors)
	}
}
