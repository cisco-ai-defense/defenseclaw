// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const hermesHotConfigProbeFixtureEnv = "HERMES_HOT_CONFIG_PROBE_FIXTURE"

// The probe executes the test binary as its installed CLI. The child models
// the public coverage refusal and the distinct registration result, so this
// test exercises the actual verb and JSON report handling together.
func init() {
	fixture := os.Getenv(hermesHotConfigProbeFixtureEnv)
	if fixture == "" {
		return
	}
	if len(os.Args) != 5 || os.Args[1] != "enterprise" || os.Args[2] != "hooks" || os.Args[4] != "--json" {
		fmt.Fprintln(os.Stderr, "unexpected hot-config hook probe arguments:", os.Args[1:])
		os.Exit(2)
	}
	row := enterpriseHookReconcileRow{SID: "S-1-5-21-1-2-3-1002", Connector: "hermes"}
	switch {
	case os.Args[3] == "verify":
		row.Error = "session-only HERMES_HOME cannot be observed"
	case os.Args[3] == "readiness" && fixture == "registered":
		row.OK = true
	case os.Args[3] == "readiness" && fixture == "absent":
		row.Error = "owned hook command not present"
	default:
		fmt.Fprintln(os.Stderr, "unexpected hot-config hook probe fixture:", fixture, os.Args[3])
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Results []enterpriseHookReconcileRow `json:"results"`
	}{Results: []enterpriseHookReconcileRow{row}}); err != nil {
		os.Exit(2)
	}
	if !row.OK {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestWindowsHotConfigHermesRegistrationProof(t *testing.T) {
	hermes := enterprisehooks.ManifestTarget{User: "operator", SID: "S-1-5-21-1-2-3-1002", Connector: "hermes"}
	publicRefusal := enterpriseHookReconcileRow{SID: hermes.SID, Connector: "hermes", Error: "session-only HERMES_HOME cannot be observed"}
	if got := windowsHotConfigUnprovenTargets([]enterprisehooks.ManifestTarget{hermes}, []enterpriseHookReconcileRow{publicRefusal}); len(got) != 1 {
		t.Fatalf("public session-home refusal proved Hermes: %+v", got)
	}
	for _, tc := range []struct {
		name     string
		unproven int
	}{
		{name: "registered", unproven: 0},
		{name: "absent", unproven: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(hermesHotConfigProbeFixtureEnv, tc.name)
			got, err := windowsEnterpriseHotConfigUnprovenTargetHooks(context.Background(), os.Args[0], managed.StandaloneLayout{}, []enterprisehooks.ManifestTarget{hermes})
			if err != nil || len(got) != tc.unproven {
				t.Fatalf("Hermes %s registration proof = (%+v, %v), want %d unproven", tc.name, got, err, tc.unproven)
			}
		})
	}
}

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
