// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func routingHealthModel() config.RoutingModelBackend {
	return config.RoutingModelBackend{Name: "fast", Provider: "ollama", Model: "qwen2.5:0.5b", BaseURL: "http://127.0.0.1:11434"}
}

// reloadRouting applies a hot reload whose only change is routing, and returns
// the routing health after it.
func reloadRouting(t *testing.T, prev, next config.RoutingConfig, before func(h *SidecarHealth)) HealthSnapshot {
	t.Helper()
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })
	NewSidecarHealth()
	t.Cleanup(func() { NewSidecarHealth() })

	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	raw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nguardrail:\n  enabled: true\n  rule_pack_dir: \"\"\nobservability: {}\n",
		fixture.dataDir,
	))
	oldCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, raw)
	if err != nil {
		t.Fatal(err)
	}
	newCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, raw)
	if err != nil {
		t.Fatal(err)
	}
	oldCfg.Routing, newCfg.Routing = prev, next
	fixture.sidecar.publishConfig(oldCfg)
	fixture.sidecar.router = NewEventRouter(nil, nil, nil, false)
	fixture.sidecar.router.generationSource = fixture.sidecar.Generation
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	compiled, err := config.ParseCompileObservabilityV8(fixture.configPath, raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: fixture.dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if before != nil {
		before(fixture.sidecar.health)
	}
	if err := fixture.sidecar.applyConfigReloadSnapshot(context.Background(), oldCfg, newCfg,
		ConfigDiff{Changed: []string{"routing"}},
		configReloadSource{sourceName: fixture.configPath, raw: raw, compiledV8: compiled},
	); err != nil {
		t.Fatalf("apply routing reload: %v", err)
	}
	return fixture.sidecar.health.Snapshot()
}

// rel-1-0-10 GAP-1744: a reload that turns routing on (or off) with a
// classifier that runs in the gateway left status at the boot value.
func TestRoutingHealthFollowsAHotReloadOfAnInGatewayClassifier(t *testing.T) {
	off := config.RoutingConfig{Classifier: config.RoutingClassifierRules, Models: []config.RoutingModelBackend{routingHealthModel()}}
	on := off
	on.Enabled = true

	snap := reloadRouting(t, off, on, func(h *SidecarHealth) {
		h.SetRouting(StateDisabled, "", map[string]interface{}{"enabled": false})
	})
	if snap.Routing.State != StateRunning || snap.Routing.Details["enabled"] != true ||
		snap.Routing.Details["classifier"] != config.RoutingClassifierRules {
		t.Fatalf("after routing.enabled true: %s %v", snap.Routing.State, snap.Routing.Details)
	}

	snap = reloadRouting(t, on, off, func(h *SidecarHealth) {
		h.SetRouting(StateRunning, "", effectiveRoutingHealthDetails(on))
	})
	if snap.Routing.State != StateDisabled || snap.Routing.Details["enabled"] != false {
		t.Fatalf("after routing.enabled false: %s %v", snap.Routing.State, snap.Routing.Details)
	}

	two := on
	two.Models = append(append([]config.RoutingModelBackend{}, on.Models...), config.RoutingModelBackend{Name: "big", Provider: "ollama", Model: "qwen2.5:7b", BaseURL: "http://127.0.0.1:11434"})
	snap = reloadRouting(t, on, two, func(h *SidecarHealth) {
		h.SetRouting(StateRunning, "", effectiveRoutingHealthDetails(on))
	})
	if snap.Routing.Details["model_count"] != 2 {
		t.Fatalf("after a second backend: %v", snap.Routing.Details)
	}
}

// A vllm_sr router is a container that starts and stops with the process: its
// health stays with boot and the probe loop across a reload.
func TestRoutingHealthOfAVLLMSRRouterIsNotRewrittenByAReload(t *testing.T) {
	vllm := config.RoutingConfig{Enabled: true, Classifier: config.RoutingClassifierVLLMSR, Models: []config.RoutingModelBackend{routingHealthModel()}}
	probeFailed := map[string]interface{}{"enabled": true, "classifier": config.RoutingClassifierVLLMSR}
	snap := reloadRouting(t, vllm, vllm, func(h *SidecarHealth) {
		h.SetRouting(StateError, modelRouterHealthProbeError, probeFailed)
	})
	if snap.Routing.State != StateError || snap.Routing.LastError != modelRouterHealthProbeError {
		t.Fatalf("a reload rewrote the vllm_sr health: %s %q", snap.Routing.State, snap.Routing.LastError)
	}
}
