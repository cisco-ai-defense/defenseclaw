// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0905: the hook proof reads the live verification rows; a target is
// proven only by its own verified row (SID and connector, whatever their
// case), or by a row pending its own Windows session. A missing or failed
// row, or a verified row of the user's other connector, proves nothing.
func TestWindowsHotConfigUnprovenTargets(t *testing.T) {
	bobClaude := enterprisehooks.ManifestTarget{User: "bob", SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode"}
	carolCodex := enterprisehooks.ManifestTarget{User: "carol", SID: "S-1-5-21-1-2-3-1003", Connector: "codex"}
	for _, tc := range []struct {
		name string
		rows []enterpriseHookReconcileRow
		want int
	}{
		{name: "no rows", want: 2},
		{name: "both verified", want: 0, rows: []enterpriseHookReconcileRow{
			{SID: "s-1-5-21-1-2-3-1002", Connector: "ClaudeCode", OK: true}, {SID: "S-1-5-21-1-2-3-1003", Connector: "codex", OK: true}}},
		{name: "one pending its session", want: 0, rows: []enterpriseHookReconcileRow{
			{SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", Pending: true}, {SID: "S-1-5-21-1-2-3-1003", Connector: "codex", OK: true}}},
		{name: "one failed", want: 1, rows: []enterpriseHookReconcileRow{
			{SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", Error: "hook missing"}, {SID: "S-1-5-21-1-2-3-1003", Connector: "codex", OK: true}}},
		{name: "the other connector of the user", want: 2, rows: []enterpriseHookReconcileRow{
			{SID: "S-1-5-21-1-2-3-1002", Connector: "codex", OK: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowsHotConfigUnprovenTargets([]enterprisehooks.ManifestTarget{bobClaude, carolCodex}, tc.rows); len(got) != tc.want {
				t.Fatalf("unproven = %+v, want %d", got, tc.want)
			}
		})
	}
}
