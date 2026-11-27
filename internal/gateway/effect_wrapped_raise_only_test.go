// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// TestWrappedCallKeepsItsCellAboveThePlainSpelling: the plain reading of a
// call behind an exact static wrapper chain (wrapperExactTwinRequest) only
// raises it. taskset 1 cp ~/.git-credentials /tmp/staged keeps the CRITICAL
// effects-lane cell it gets at T23d 886dcf3118 (block in strict, managed and
// managed strict, alert in default and permissive) though the plain cp
// alerts MEDIUM: parity raises the lower form, never lowers the higher one
// (R-NOLOSS; DET111 ruling 2026-11-25T01:30Z; gen TST-16272 rows).
func TestWrappedCallKeepsItsCellAboveThePlainSpelling(t *testing.T) {
	home := r2Home(t)
	useDefaultLaneGeneration(t)
	var commands []string
	for _, w := range []string{"chrt -i 0", "flock /tmp/d111.lock", "ionice -c3", "nohup nice setsid", "setsid",
		"setsid -w", "setsid nohup", "stdbuf -oL", "taskset -c 0", "taskset 1"} {
		commands = append(commands, w+" cp ~/.git-credentials /tmp/staged")
	}
	for _, tier := range boundedTestTiers {
		want := "block"
		if tier.name == "default" || tier.name == "permissive" {
			want = "alert"
		}
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, command := range commands {
				action, severity, rules := r2Verdict(api, connector, home+"/proj", command)
				if action != want || severity != "CRITICAL" {
					t.Errorf("%s %s %q: %s/%s %v, want %s/CRITICAL", tier.name, connector, command, action, severity, rules, want)
				}
			}
		}
	}
}
