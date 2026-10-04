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

package audit

import (
	"slices"
	"testing"
	"time"
)

// GAP-2619: alerts show copilot:preToolUse for both the VS Code Local
// harness (stored copilot:PreToolUse) and the Copilot CLI (stored
// copilot:preToolUse); --target with the shown value selects both.
func TestAlertTargetSelectorMatchesBothCopilotHarnessSpellings(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 4, 16, 0, 0, 0, time.UTC)
	for i, event := range []Event{
		{ID: "cli", Target: "copilot:preToolUse", Connector: "copilot"},
		{ID: "local", Target: "copilot:PreToolUse", Connector: "copilot"},
		{ID: "bare-cli", Target: "preToolUse", Connector: "copilot"},
		{ID: "bare-local", Target: "PreToolUse", Connector: "copilot"},
		{ID: "claude", Target: "PreToolUse", Connector: "claudecode"},
		{ID: "claude-prefixed", Target: "claudecode:PreToolUse", Connector: "claudecode"},
	} {
		event.Timestamp = base.Add(time.Duration(i) * time.Second)
		event.Action, event.Severity = "scan-finding", "HIGH"
		if err := store.LogEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	for target, want := range map[string][]string{
		"copilot:preToolUse":    {"cli", "local"},
		"copilot:PreToolUse":    {"cli", "local"},
		"preToolUse":            {"bare-cli", "bare-local"},
		"PreToolUse":            {"bare-cli", "bare-local", "claude"},
		"claudecode:PreToolUse": {"claude-prefixed"},
		"copilot:sessionEnd":    nil,
	} {
		got, err := store.SelectAlertAcknowledgementTargets(t.Context(), AlertAcknowledgementSelector{Target: target})
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(got))
		for _, item := range got {
			ids = append(ids, item.AlertID)
		}
		slices.Sort(ids)
		slices.Sort(want)
		if !slices.Equal(ids, want) {
			t.Errorf("--target %q selected %v, want %v", target, ids, want)
		}
	}
}
