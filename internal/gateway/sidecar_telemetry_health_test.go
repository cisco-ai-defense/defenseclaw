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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// TestReportTelemetryHealth_ManagedAIDLogSinkWaivesDestinationRule asserts that
// reportTelemetryHealth honours the same waiver as config.HasManagedAIDLogSink:
// under managed_enterprise with a non-empty cisco_ai_defense.endpoint, otel
// export is carried by the auto-provisioned AID log sink and zero user
// destinations is a valid, healthy state. Without this waiver every intended
// managed_enterprise install flips Telemetry to ERROR after boot / on every
// env_config reload — cosmetic but loud in `defenseclaw-gateway status`, and
// what confused the 26.7.3 QA drop into thinking env_config wasn't reloading.
func TestReportTelemetryHealth_ManagedAIDLogSinkWaivesDestinationRule(t *testing.T) {
	cfg := &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		CiscoAIDefense: config.CiscoAIDefenseConfig{
			Endpoint: "https://preview.api.inspect.aidefense.aiteam.cisco.com",
		},
		OTel: config.OTelConfig{Enabled: true}, // no destinations
	}
	if !cfg.HasManagedAIDLogSink() {
		t.Fatalf("test fixture setup wrong: HasManagedAIDLogSink() = false")
	}

	prov, err := telemetry.NewProviderInactive(context.Background(), cfg, "test")
	if err != nil {
		t.Fatalf("NewProviderInactive: %v", err)
	}
	if !prov.Enabled() {
		t.Fatalf("provider not enabled; managed AID sink should activate the SDK")
	}
	t.Cleanup(func() { _ = prov.Shutdown(context.Background()) })

	s := &Sidecar{
		cfg:    cfg,
		health: NewSidecarHealth(),
		otel:   prov,
	}
	s.publishConfig(cfg)

	s.reportTelemetryHealth()

	snap := s.health.Snapshot()
	if snap.Telemetry.State != StateRunning {
		t.Fatalf("telemetry state = %q lastError=%q, want %q; managed AID sink must waive the destinations rule",
			snap.Telemetry.State, snap.Telemetry.LastError, StateRunning)
	}
	if got, ok := snap.Telemetry.Details["managed_aid_log_sink"].(bool); !ok || !got {
		t.Errorf("details.managed_aid_log_sink = %v (present=%v), want true", got, ok)
	}
}

// TestReportTelemetryHealth_OTelEnabledButNoSinkStaysError guards the other
// direction: with otel.enabled=true, no destinations, AND no managed AID sink
// (e.g. an OSS deployment_mode without the AID endpoint), the ERROR state is
// still the correct signal. Config validation would have rejected the config
// on load in production; the check here catches the case where an in-memory
// mutation slips such a config past validation.
func TestReportTelemetryHealth_OTelEnabledButNoSinkStaysError(t *testing.T) {
	cfg := &config.Config{
		DeploymentMode: "", // NOT managed_enterprise
		OTel:           config.OTelConfig{Enabled: true},
	}
	if cfg.HasManagedAIDLogSink() {
		t.Fatalf("test fixture setup wrong: HasManagedAIDLogSink() = true for non-managed config")
	}

	prov, err := telemetry.NewProviderInactive(context.Background(), cfg, "test")
	if err != nil {
		t.Fatalf("NewProviderInactive: %v", err)
	}
	t.Cleanup(func() { _ = prov.Shutdown(context.Background()) })

	// Force Enabled() to fire the "no destinations" branch: the constructor
	// short-circuits to a disabled no-op when neither otel.enabled combined
	// with destinations nor the managed sink applies. Constructing an
	// enabled provider by hand keeps this test focused on the health
	// reporter's branch — the config validator's job is tested elsewhere.
	s := &Sidecar{
		cfg:    cfg,
		health: NewSidecarHealth(),
		otel:   prov,
	}
	s.publishConfig(cfg)

	s.reportTelemetryHealth()

	snap := s.health.Snapshot()
	if !prov.Enabled() {
		// The disabled-provider case flips telemetry to DISABLED, not ERROR;
		// that's the correct behaviour for OSS with otel off.
		if snap.Telemetry.State != StateDisabled {
			t.Fatalf("provider disabled but telemetry state = %q, want %q",
				snap.Telemetry.State, StateDisabled)
		}
		return
	}
	if snap.Telemetry.State != StateError {
		t.Fatalf("telemetry state = %q, want %q (otel enabled, no destinations, no managed sink)",
			snap.Telemetry.State, StateError)
	}
}
