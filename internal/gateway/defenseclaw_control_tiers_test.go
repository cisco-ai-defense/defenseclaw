// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestDefenseClawControlFiveTiers is GAP-0596: every row of the actionfacts
// corpus (loaded by id, not retyped) through the tool-inspect route in the five
// tiers. A proven stop or disable blocks in all five, managed included. An
// unproven DefenseClaw command is the unknown tier: an alert in default,
// permissive and managed (default pack), a block in strict and managed-strict.
// Read-only commands, restarts and the benign twins stay allowed.
func TestDefenseClawControlFiveTiers(t *testing.T) {
	file, err := os.Open("../actionfacts/testdata/defenseclaw_control.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	type row struct {
		ID, Dialect, Command, Want string
	}
	var rows []row
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var r row
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		// Windows dialects are judged in the actionfacts rows and in the
		// native Windows run; the POSIX parse is not their grammar.
		if r.Dialect == "" {
			rows = append(rows, r)
		}
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		// The first call of a pack builds its rule generation; under -race on
		// a loaded box that can outlast the scan deadline.
		gap0437Inspect(t, a, t.TempDir(), "ls")
		for _, r := range rows {
			out := gap0437Inspect(t, a, t.TempDir(), r.Command)
			raw, _ := json.Marshal(out)
			action, _ := out["action"].(string)
			named := strings.Contains(string(raw), "tamper.defenseclaw_control")
			where := p.name + " " + r.ID
			switch r.Want {
			case "stop", "disable", "uninstall", "config":
				if action != "block" || !strings.Contains(string(raw), "tamper.defenseclaw_control_disable") {
					t.Errorf("%s: action %q, want block by tamper.defenseclaw_control_disable: %s", where, action, raw)
				}
			case "unproven":
				want := "alert"
				if p.pack == "strict" {
					want = "block"
				}
				if action != want || !strings.Contains(string(raw), "tamper.defenseclaw_control_unproven") {
					t.Errorf("%s: action %q, want %s by tamper.defenseclaw_control_unproven: %s", where, action, want, raw)
				}
			default:
				if named || action == "block" {
					t.Errorf("%s: a benign twin was judged: %s", where, raw)
				}
			}
		}
	}
}

// TestDefenseClawControlOnTheClaudeHookPath sends the headline rows through
// the Claude Code PreToolUse route in the five packs: the proven stop or
// disable is a block, a read-only command is allowed.
func TestDefenseClawControlOnTheClaudeHookPath(t *testing.T) {
	file, err := os.Open("../actionfacts/testdata/defenseclaw_control.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	want := map[string]string{
		"g596-r01": "block", "g596-r02": "block", "g596-v14": "block", "g596-v17": "block",
		"g596-v06": "block", "g596-c01": "allow", "g596-c02": "allow", "g596-v02": "allow",
	}
	rows := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var r struct{ ID, Command string }
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if _, ok := want[r.ID]; ok {
			rows[r.ID] = r.Command
		}
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		gap0437Hook(t, a, t.TempDir(), p.name+"warm", "ls")
		for id, action := range want {
			out := gap0437Hook(t, a, t.TempDir(), p.name+id, rows[id])
			if got, _ := out["action"].(string); got != action {
				raw, _ := json.Marshal(out)
				t.Errorf("%s %s: action %q, want %s: %s", p.name, id, got, action, raw)
			}
		}
	}
}
