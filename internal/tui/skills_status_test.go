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

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// TestSkillListToItem_StatusPrecedence pins the status precedence
// against cli/defenseclaw/commands/cmd_skill.py::_skill_status_display.
// Any drift between the two will cause operators to see different
// verdicts in the TUI vs. `defenseclaw skill list` for the same
// backing data.
func TestSkillListToItem_StatusPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		in         skillListJSON
		wantStatus string
	}{
		{
			name:       "disabled flag wins over everything",
			in:         skillListJSON{Name: "a", Disabled: true, Eligible: true, Scan: &skillScanJSON{MaxSeverity: "CRITICAL"}},
			wantStatus: "disabled",
		},
		{
			name:       "quarantined action wins over other actions",
			in:         skillListJSON{Name: "a", Eligible: true, Actions: &audit.ActionState{File: "quarantine", Install: "block"}},
			wantStatus: "quarantined",
		},
		{
			name:       "install=block",
			in:         skillListJSON{Name: "a", Eligible: true, Actions: &audit.ActionState{Install: "block"}},
			wantStatus: "blocked",
		},
		{
			name:       "runtime=disable",
			in:         skillListJSON{Name: "a", Eligible: true, Actions: &audit.ActionState{Runtime: "disable"}},
			wantStatus: "disabled",
		},
		{
			name:       "install=allow",
			in:         skillListJSON{Name: "a", Eligible: true, Actions: &audit.ActionState{Install: "allow"}},
			wantStatus: "allowed",
		},
		{
			name:       "dirty scan HIGH → rejected (even when eligible)",
			in:         skillListJSON{Name: "a", Eligible: true, Scan: &skillScanJSON{Clean: false, MaxSeverity: "HIGH", TotalFindings: 3}},
			wantStatus: "rejected",
		},
		{
			name:       "dirty scan CRITICAL → rejected",
			in:         skillListJSON{Name: "a", Eligible: true, Scan: &skillScanJSON{Clean: false, MaxSeverity: "CRITICAL", TotalFindings: 1}},
			wantStatus: "rejected",
		},
		{
			name:       "dirty scan MEDIUM → warning",
			in:         skillListJSON{Name: "a", Eligible: true, Scan: &skillScanJSON{Clean: false, MaxSeverity: "MEDIUM", TotalFindings: 1}},
			wantStatus: "warning",
		},
		{
			name:       "dirty scan LOW → warning",
			in:         skillListJSON{Name: "a", Eligible: true, Scan: &skillScanJSON{Clean: false, MaxSeverity: "LOW", TotalFindings: 1}},
			wantStatus: "warning",
		},
		{
			name:       "clean scan with eligible → active",
			in:         skillListJSON{Name: "a", Eligible: true, Scan: &skillScanJSON{Clean: true, MaxSeverity: "CLEAN"}},
			wantStatus: "active",
		},
		{
			name:       "clean scan CRITICAL sentinel ignored (no findings)",
			in:         skillListJSON{Name: "a", Eligible: true, Scan: &skillScanJSON{Clean: true, MaxSeverity: "CRITICAL", TotalFindings: 0}},
			wantStatus: "active",
		},
		{
			name:       "no scan, eligible → active",
			in:         skillListJSON{Name: "a", Eligible: true},
			wantStatus: "active",
		},
		{
			name:       "no scan, source=scan-history → removed",
			in:         skillListJSON{Name: "a", Source: "scan-history"},
			wantStatus: "removed",
		},
		{
			name:       "no scan, source=enforcement → removed",
			in:         skillListJSON{Name: "a", Source: "enforcement"},
			wantStatus: "removed",
		},
		{
			name:       "no scan, no eligibility, no source → inactive",
			in:         skillListJSON{Name: "a"},
			wantStatus: "inactive",
		},
		{
			name:       "explicit status=blocked",
			in:         skillListJSON{Name: "a", Status: "blocked"},
			wantStatus: "blocked",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := skillListToItem(tc.in)
			if got.Status != tc.wantStatus {
				t.Errorf("status: got %q, want %q", got.Status, tc.wantStatus)
			}
		})
	}
}

// TestStatusBadge_KnownLabels guarantees each label that
// skillListToItem can emit also renders to a styled badge. Without
// this the new "rejected" / "warning" statuses would silently fall
// through to the neutral grey default, defeating the whole point of
// porting the severity branch from the CLI.
func TestStatusBadge_KnownLabels(t *testing.T) {
	labels := []string{
		"blocked", "allowed", "quarantined", "rejected",
		"warning", "active", "removed", "disabled", "inactive",
	}
	for _, label := range labels {
		out := statusBadge(label)
		// All badges should echo the label in upper case, and must
		// be wrapped in at least one ANSI sequence (so the caller
		// knows they were styled, not just pass-through text).
		if !strings.Contains(out, strings.ToUpper(label)) {
			t.Errorf("%s: badge %q did not contain upper-cased label", label, out)
		}
		if !strings.Contains(out, "\x1b[") {
			t.Errorf("%s: badge did not include any ANSI escape (expected styling): %q", label, out)
		}
	}
}
