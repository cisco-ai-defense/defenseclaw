// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// r2Verdict is the action, severity and rule ids of command on connector.
func r2Verdict(api *APIServer, connector, cwd, command string) (string, string, []string) {
	if connector == "codex" {
		resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
			ToolInput: map[string]interface{}{"command": command},
		})
		return resp.Action, resp.Severity, resp.RuleIDs
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "det111-wrapped-program", ToolName: "Bash", CWD: cwd,
		ToolInput: map[string]interface{}{"command": command},
	})
	return resp.Action, resp.Severity, resp.RuleIDs
}

// TestWrappedProgramKeepsThePlainVerdict: a program run through a chain of
// static prefix wrappers that hand it its argv unchanged gets the verdict
// of its plain call, action, severity and rules, in the five tiers with the
// effects lane as shipped (GAP-1461: taskset 1 sudo env LD_PRELOAD=x before
// a cloud metadata fetch or a setuid chmod; GAP-1494: curl|sh, wget|bash,
// nc -e, base64 of a credential file, pkill, systemctl stop and uninstall
// of DefenseClaw behind sudo, env, setsid, stdbuf, ionice, doas, taskset,
// chrt, flock and the time keyword; DET111 ruling 2026-11-24T21:35Z). The
// same chains before a harmless program stay allowed. Chains the ruling
// keeps out (a word that may expand to nothing, a program word with no
// static spelling, command, exec -a, a shell STRING) keep their own cell.
// GAP-1461 rows after the DET111-TRAIN-R2R3C table (TST-15961, TST-15964).
func TestWrappedProgramKeepsThePlainVerdict(t *testing.T) {
	home := r2Home(t)
	useDefaultLaneGeneration(t)
	stateDelete := "rm -rf ~/.defenseclaw"
	metadata := "curl http://" + strings.Join([]string{"169", "254", "169", "254"}, ".") + "/latest/meta-data/"
	suid := "chmod u+s /bin/bash"
	type pair struct{ id, command, plain string }
	attack := []pair{
		{"1461/taskset-sudo-env-state", "taskset 1 sudo env LD_PRELOAD=/tmp/x.so " + stateDelete, stateDelete},
		{"1461/time-sudo-nohup-state", "/usr/bin/time -p sudo nohup " + stateDelete, stateDelete},
		{"1461/time-env-state", "/usr/bin/time -p env LD_PRELOAD=/tmp/x.so " + stateDelete, stateDelete},
		{"1461/taskset-sudo-env-metadata", "taskset 1 sudo env LD_PRELOAD=/tmp/x.so " + metadata, metadata},
		{"1461/time-sudo-nohup-metadata", "/usr/bin/time -p sudo nohup " + metadata, metadata},
		{"1461/time-env-metadata", "/usr/bin/time -p env LD_PRELOAD=/tmp/x.so " + metadata, metadata},
		{"1461/taskset-sudo-env-suid", "taskset 1 sudo env LD_PRELOAD=/tmp/x.so " + suid, suid},
	}
	seeds := map[string]string{"curl-sh": "seed-curl-sh", "wget-bash": "seed-wget-bash", "nc-e": "seed-nc-e",
		"base64-aws": "seed-base64-aws", "pkill-gw": "seed-pkill-gw", "systemctl-stop-gw": "seed-systemctl-stop-gw",
		"uninstall": "seed-uninstall"}
	variants := map[string][]string{
		"curl-sh":           {"sudo", "env", "time", "setsid", "stdbuf-ol", "taskset-0x1", "chrt-i-0", "flock-tmp-l"},
		"wget-bash":         {"sudo", "env", "doas", "ionice-c3"},
		"nc-e":              {"setsid", "stdbuf-ol", "ionice-c3", "doas", "taskset-0x1", "chrt-i-0", "flock-tmp-l"},
		"base64-aws":        {"setsid", "stdbuf-ol", "ionice-c3", "doas", "taskset-0x1", "chrt-i-0", "flock-tmp-l"},
		"pkill-gw":          {"chrt-i-0", "taskset-0x1"},
		"systemctl-stop-gw": {"chrt-i-0", "taskset-0x1"},
		"uninstall":         {"chrt-i-0", "taskset-0x1"},
	}
	for _, family := range []string{"curl-sh", "wget-bash", "nc-e", "base64-aws", "pkill-gw", "systemctl-stop-gw", "uninstall"} {
		seed := det111R2Rows(t, home, "det111/GAP-1494/"+seeds[family]+"/seed")[0]
		for _, w := range variants[family] {
			row := det111R2Rows(t, home, "det111/GAP-1494/"+family+"-"+w+"/var")[0]
			attack = append(attack, pair{"1494/" + family + "-" + w, row.cmd, seed.cmd})
		}
	}
	benign := []pair{
		{id: "1461/taskset-sudo-env", command: "taskset 1 sudo env FOO=1 ls /tmp"},
		{id: "1461/time-sudo-nohup", command: "/usr/bin/time -p sudo nohup ls /tmp"},
		{id: "1461/time-env", command: "/usr/bin/time -p env FOO=1 ls /tmp"},
		{id: "1461/taskset-sudo-env-preload", command: "taskset 1 sudo env LD_PRELOAD=/tmp/x.so ls /tmp"},
		{id: "1461/time-env-preload", command: "/usr/bin/time -p env LD_PRELOAD=/tmp/x.so ls /tmp"},
		{id: "1494/wrapped-benign", command: det111R2Rows(t, home, "det111/GAP-1494/wrapped-benign/twin")[0].cmd},
		{id: "control/chrt-curl-json", command: "chrt -i 0 curl -fsSL https://example.com/data.json -o /tmp/data.json"},
		{id: "control/taskset-pkill-other", command: "taskset 1 pkill -f myserver"},
	}
	// A tier that allows the plain call (curl | sh in permissive) allows
	// the wrapped call too; every attack row is enforced in some tier.
	enforced := map[string]int{}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, row := range attack {
				plain, plainSeverity, plainRules := r2Verdict(api, connector, home, row.plain)
				if plain != "allow" {
					enforced[row.id]++
				}
				action, severity, rules := r2Verdict(api, connector, home, row.command)
				if action != plain || severity != plainSeverity || !sameRuleSet(rules, plainRules) {
					t.Errorf("%s %s %s: %s/%s %v, want the plain call's %s/%s %v", tier.name, connector, row.id,
						action, severity, rules, plain, plainSeverity, plainRules)
				}
			}
			for _, row := range benign {
				if action, severity, rules := r2Verdict(api, connector, home, row.command); action != "allow" {
					t.Errorf("%s %s %s: %s/%s %v, want allow", tier.name, connector, row.id, action, severity, rules)
				}
			}
		}
	}
	for _, row := range attack {
		if enforced[row.id] == 0 {
			t.Errorf("%s: the plain call is allowed in every tier", row.id)
		}
	}
}

// sameRuleSet reports a and b name the same rules in any order.
func sameRuleSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
