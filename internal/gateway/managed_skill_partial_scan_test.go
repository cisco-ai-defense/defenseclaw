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
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestSkillInventoryCompletenessControlsSummaryAndCommit(t *testing.T) {
	withManagedEnterprise(t, true)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	type scanCase struct {
		name        string
		mutate      func(*inventory.AIDiscoveryReport)
		wantManaged bool
	}
	cases := []scanCase{
		{"unrelated_detector", func(r *inventory.AIDiscoveryReport) {
			r.Summary.DetectorErrors = map[string]string{"model_file": "permission denied"}
		}, true},
		{"scoped_model_file", func(r *inventory.AIDiscoveryReport) {
			r.Summary.DetectorErrors = map[string]string{"model_file:fixture-root": "permission denied"}
		}, true},
		{"skill_detector", func(r *inventory.AIDiscoveryReport) {
			r.Summary.DetectorErrors = map[string]string{"skill_dir": "permission denied"}
		}, false},
		{"user_scan", func(r *inventory.AIDiscoveryReport) {
			r.Summary.DetectorErrors = map[string]string{"user_scan_fixture": "permission denied"}
		}, false},
		{"partial_skill_signal", func(r *inventory.AIDiscoveryReport) {
			r.Signals[0].Partial = true
		}, false},
		{"partial_skill_with_ok_summary", func(r *inventory.AIDiscoveryReport) {
			r.Summary.Result = "ok"
			r.Signals[0].Partial = true
		}, false},
		{"unattributed_partial", func(*inventory.AIDiscoveryReport) {}, false},
		{"missing_result", func(r *inventory.AIDiscoveryReport) {
			r.Summary.Result = ""
		}, false},
		{"known_and_global_errors", func(r *inventory.AIDiscoveryReport) {
			r.Summary.DetectorErrors = map[string]string{
				"model_file":  "permission denied",
				"state_store": "write failed",
			}
		}, false},
	}
	for _, key := range []string{
		"macos_privacy", "state_store", "sandbox_scan", "sandbox_scan:fixture",
		"sandbox_collect", "project_skill", "future_detector", "model_file:", "model_file_extra",
	} {
		cases = append(cases, scanCase{
			name: key,
			mutate: func(r *inventory.AIDiscoveryReport) {
				r.Summary.DetectorErrors = map[string]string{key: "incomplete scan"}
			},
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := managedPublishTestState(t)
			cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("codex")}}
			registry := connector.NewDefaultRegistry()
			emit := func(report inventory.AIDiscoveryReport) []observability.Record {
				t.Helper()
				capture := &endpointInventoryCapture{}
				if err := emitEndpointInventory(t.Context(), cfg, registry, capture, false, &report, gate); err != nil {
					t.Fatal(err)
				}
				return capture.snapshot()
			}
			check := func(records []observability.Record, managed bool) map[string]string {
				t.Helper()
				states := map[string]string{}
				summaries := 0
				for _, record := range records {
					body := canonicalBody(t, record)
					if body[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != endpointSkillInventorySource {
						continue
					}
					wantAction := config.ObservabilityV8LocalInventoryDiagnosticAction
					wantOutcome := observability.OutcomePartial
					if managed {
						wantAction = config.ObservabilityV8ManagedSkillInventoryAction
						wantOutcome = observability.OutcomeCompleted
					}
					if record.Action() != string(wantAction) {
						t.Fatalf("skill record action = %q, want %q", record.Action(), wantAction)
					}
					if record.EventName() == "ai.discovery.completed" {
						summaries++
						if record.Outcome() != wantOutcome {
							t.Fatalf("skill summary outcome = %q, want %q", record.Outcome(), wantOutcome)
						}
						continue
					}
					name, _ := body[observability.TelemetryAttributeDefenseClawInventoryItemName].(string)
					states[name], _ = body[observability.TelemetryAttributeDefenseClawInventorySkillState].(string)
				}
				if summaries != 1 {
					t.Fatalf("skill summaries = %d, want 1", summaries)
				}
				return states
			}

			check(emit(managedGateReport("baseline", "alpha", "beta")), true)
			before := managedPublishReadFile(t, gate)
			partial := managedGateReport("partial", "alpha", "delta")
			partial.Summary.Result = aiDiscoveryResultPartial
			tc.mutate(&partial)
			states := check(emit(partial), tc.wantManaged)
			after := managedPublishReadFile(t, gate)
			if !after.FullBundleAt.Equal(before.FullBundleAt) {
				t.Fatal("incomplete report advanced the daily bundle clock")
			}
			if tc.wantManaged {
				if states["beta"] != skillStateRemoved || states["delta"] != skillStateNew {
					t.Fatalf("complete skill collection with unrelated failure = %v", states)
				}
			} else {
				if states["beta"] == skillStateRemoved {
					t.Fatalf("partial skill collection emitted removal: %v", states)
				}
				if !reflect.DeepEqual(before.Skills, after.Skills) ||
					!reflect.DeepEqual(before.Collections[endpointSkillInventorySource], after.Collections[endpointSkillInventorySource]) {
					t.Fatal("diagnostic skill snapshot advanced durable skill state or publish digest")
				}
				states = check(emit(managedGateReport("recovered", "alpha", "delta")), true)
				if states["delta"] != skillStateNew || states["beta"] != skillStateRemoved {
					t.Fatalf("next complete scan lost pending creation/removal: %v", states)
				}
			}
		})
	}
}
