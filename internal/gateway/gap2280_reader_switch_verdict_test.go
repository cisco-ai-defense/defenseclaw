// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestGAP2280ReaderSwitchReadIsJudgedAsThePlainRead: a text reader given a
// switch (column -t, od -c, strings -d, fmt -t, look -d) or a valued option
// (column -s SEP, hexdump -n LEN) reads the same file as the plain call, so
// the hook gives the same action in every bounded tier on both routes, for a
// credential file and for an ordinary one. Red at 78506d3a71: the readers
// shared one flag set that gave these switches a value, so the file operand
// was taken as the value and the credential read went unattributed (column -t
// was allowed where column blocked).
func TestGAP2280ReaderSwitchReadIsJudgedAsThePlainRead(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{".ssh/id_rsa", "proj/notes.txt"} {
		p := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // the active home on Windows
	useEffectsRulesMode(t, "on")  // the shipped default (config.CascadeLaneEffects Default on)
	cwd := filepath.Join(home, "proj")
	type row struct{ command, twin string }
	var rows []row
	for _, file := range []string{"~/.ssh/id_rsa", "notes.txt"} {
		rows = append(rows, []row{
			{"column -t " + file, "column " + file},
			{"column -s , -t " + file, "column " + file},
			{"column -x " + file, "column " + file},
			{"od -c " + file, "od " + file},
			{"od -d " + file, "od " + file},
			{"od -An -tx1 " + file, "od " + file},
			{"strings -d " + file, "strings " + file},
			{"strings -o " + file, "strings " + file},
			{"strings -w " + file, "strings " + file},
			{"fmt -t " + file, "fmt " + file},
			{"fmt -c " + file, "fmt " + file},
			{"fold -s " + file, "fold " + file},
			{"hexdump -n 16 " + file, "hexdump " + file},
			{"hexdump -C " + file, "hexdump " + file},
			{"look -d x " + file, "look x " + file},
			{"paste -d , " + file, "paste " + file},
			{"expand -t 4 " + file, "expand " + file},
		}...)
	}
	action := func(api *APIServer, connector, command string) string {
		if connector == "codex" {
			return api.evaluateCodexHook(context.Background(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}
		return api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "gap2280", ToolName: "Bash", CWD: cwd,
			ToolInput: map[string]interface{}{"command": command},
		}).Action
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range hardP5Routes() {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			if tier.name == "default" {
				// The plain credential read is enforced, so the rows below
				// compare against a verdict, not two allows.
				if got := action(api, connector, "column ~/.ssh/id_rsa"); got == "allow" {
					t.Fatalf("%s %s: the plain credential read is allow", tier.name, connector)
				}
			}
			for _, r := range rows {
				if got, want := action(api, connector, r.command), action(api, connector, r.twin); got != want {
					t.Errorf("%s %s %q: %s, the plain read %q is %s", tier.name, connector, r.command, got, r.twin, want)
				}
			}
		}
	}
}
