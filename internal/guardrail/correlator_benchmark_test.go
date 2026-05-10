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

package guardrail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type flowEvent struct {
	RuleID              string `json:"rule_id,omitempty"`
	Severity            string `json:"severity"`
	ContentFingerprint  string `json:"content_fingerprint,omitempty"`
	ToolCapabilityClass string `json:"tool_capability_class,omitempty"`
}

type flowCase struct {
	ID              string      `json:"id"`
	Description     string      `json:"description,omitempty"`
	Events          []flowEvent `json:"events"`
	ExpectFires     []string    `json:"expect_fires,omitempty"`
	ExpectNotFires  []string    `json:"expect_not_fires,omitempty"`
}

type flowsFile struct {
	Flows []flowCase `json:"flows"`
}

// TestCorrelatorBenchmark runs the declared multi-turn flows against
// the correlator pattern library and asserts which CORR-* patterns
// should fire (or not) per scenario. This is the multi-step analog
// of the gateway severity benchmark — a change to the pattern YAML
// or matcher logic that breaks one of these flows shows up here.
func TestCorrelatorBenchmark(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "correlator_flows", "flows.json"))
	if err != nil {
		t.Fatalf("read correlator flows: %v", err)
	}
	var file flowsFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse correlator flows: %v", err)
	}
	if len(file.Flows) == 0 {
		t.Fatal("no flows to run")
	}

	set, err := DefaultCorrelationPatterns()
	if err != nil {
		t.Fatalf("load default patterns: %v", err)
	}

	for _, flow := range file.Flows {
		flow := flow
		t.Run(flow.ID, func(t *testing.T) {
			// Build the sliding window in newest-first order —
			// the matcher expects input in the same shape
			// ListRecentFindingsInSession returns.
			window := make([]CorrelationFinding, 0, len(flow.Events))
			for i := len(flow.Events) - 1; i >= 0; i-- {
				e := flow.Events[i]
				window = append(window, CorrelationFinding{
					ID:                  "ev-" + flow.ID + "-" + string(rune('A'+i)),
					RuleID:              e.RuleID,
					Severity:            e.Severity,
					ContentFingerprint:  e.ContentFingerprint,
					ToolCapabilityClass: ToolCapabilityClass(e.ToolCapabilityClass),
					DataAxis:            AxesForRuleID(e.RuleID),
				})
			}

			matches := Evaluate(set.Patterns, window)
			fired := map[string]bool{}
			for _, m := range matches {
				fired[m.Pattern.ID] = true
			}

			for _, want := range flow.ExpectFires {
				if !fired[want] {
					t.Errorf("expected %s to fire, got fired=%s",
						want, firedList(fired))
				}
			}
			for _, forbidden := range flow.ExpectNotFires {
				if fired[forbidden] {
					t.Errorf("%s fired but should not have; fired=%s",
						forbidden, firedList(fired))
				}
			}
		})
	}
}

func firedList(fired map[string]bool) string {
	if len(fired) == 0 {
		return "[]"
	}
	ids := make([]string, 0, len(fired))
	for id := range fired {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := "["
	for i, id := range ids {
		if i > 0 {
			out += " "
		}
		out += id
	}
	return out + "]"
}
