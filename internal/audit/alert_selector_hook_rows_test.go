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

// GAP-0166: a hook block that a rule finding explains is listed once, as the
// finding. A selector (acknowledge, dismiss) matches only what the alert list
// shows, so it must not pick up the connector-hook row of the same request.
func TestAlertSelectorSkipsHookRowExplainedByFinding(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 31, 6, 0, 0, 0, time.UTC)
	for i, event := range []Event{
		{ID: "finding", Action: "scan-finding", Severity: "CRITICAL", Target: "claudecode:PreToolUse",
			Connector: "claudecode", RequestID: "req-1"},
		{ID: "hook", Action: "connector-hook", Severity: "INFO", Target: "PreToolUse",
			Connector: "claudecode", RequestID: "req-1", Enforced: true},
		{ID: "lone-hook", Action: "connector-hook", Severity: "INFO", Target: "PreToolUse",
			Connector: "claudecode", RequestID: "req-2", Enforced: true},
	} {
		event.Timestamp = base.Add(time.Duration(i) * time.Second)
		if err := store.LogEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	for name, selector := range map[string]AlertAcknowledgementSelector{
		"target":    {Connector: "claudecode", Target: "PreToolUse"},
		"connector": {Connector: "claudecode"},
		"all":       {},
	} {
		got, err := store.SelectAlertAcknowledgementTargets(t.Context(), selector)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(got))
		for _, item := range got {
			ids = append(ids, item.AlertID)
		}
		slices.Sort(ids)
		if slices.Contains(ids, "hook") {
			t.Errorf("%s selector %v matched the hook row the alert list does not show", name, ids)
		}
		if !slices.Contains(ids, "lone-hook") {
			t.Errorf("%s selector %v lost a hook block that has no finding", name, ids)
		}
	}
}
