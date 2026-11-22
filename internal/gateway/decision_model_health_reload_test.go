// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestDecisionModelHealthStartsOverOnAHotReload pins GAP-1596: after an
// operator fixes or turns off a dead decision model and the gateway hot
// reloads, status and doctor no longer show the old endpoint's failures. The
// reload starts a new decision-model window, as it does for the judge.
func TestDecisionModelHealthStartsOverOnAHotReload(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })
	NewSidecarHealth()
	t.Cleanup(func() { NewSidecarHealth() }) // resets the health windows

	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	raw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nguardrail:\n  enabled: true\n  rule_pack_dir: \"\"\nobservability: {}\n",
		fixture.dataDir,
	))
	oldCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, raw)
	if err != nil {
		t.Fatalf("load old config: %v", err)
	}
	newCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, raw)
	if err != nil {
		t.Fatalf("load new config: %v", err)
	}
	// The old generation ran a decision model at a dead endpoint; the operator
	// turned it off.
	oldCfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: "http://127.0.0.1:9",
		HookConnectors: []string{"claudecode"}}
	newCfg.DecisionModel = config.DecisionModelConfig{}
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
		t.Fatalf("compile observability plan: %v", err)
	}

	for i := 0; i < 3; i++ {
		decisionModelHealth.record(true, "dial tcp 127.0.0.1:9: connection refused", time.Now())
	}
	if d := decisionModelHealth.details(); d == nil || d["decision_model_state"] != "failing" {
		t.Fatalf("before reload decision-model health = %v, want failing", d)
	}

	if err := fixture.sidecar.applyConfigReloadSnapshot(context.Background(), oldCfg, newCfg,
		ConfigDiff{Changed: []string{"decision_model"}},
		configReloadSource{sourceName: fixture.configPath, raw: raw, compiledV8: compiled},
	); err != nil {
		t.Fatalf("apply decision-model reload: %v", err)
	}
	if d := decisionModelHealth.details(); d != nil {
		t.Fatalf("after reload decision-model health = %v, want a new window (no details before the first call)", d)
	}
}
