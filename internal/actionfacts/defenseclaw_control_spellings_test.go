// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// provenControlKinds are the kinds a row of the corpus can prove.
var provenControlKinds = map[string]bool{"stop": true, "disable": true, "uninstall": true, "config": true, "substrate": true}

func shellQuoteForTest(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func readableForTransform(row defenseClawControlRow) bool {
	return row.Dialect == "" && !strings.ContainsAny(row.Command, "\n|&;$`<>(){}") && !strings.Contains(row.Command, "'")
}

// TestDefenseClawControlWrappedSpellings is GAP-0697, GAP-0698, GAP-0699 and
// GAP-0704 over the rows that already exist: every proven row of the corpus is
// carried through the other ways a call can spell it (a nested shell opened
// with a combined flag, another shell, su, sudo -i, find -exec, xargs, a
// program named with ~ or $HOME, ssh to this host) and must keep its verdict;
// what runs through ssh to this host is at least the unknown tier, and ssh to another machine is not this host's guard.
func TestDefenseClawControlWrappedSpellings(t *testing.T) {
	var checked int
	for _, row := range loadDefenseClawControlRows(t) {
		if !readableForTransform(row) || !provenControlKinds[row.Want] {
			continue
		}
		quoted := shellQuoteForTest(row.Command)
		same := map[string]string{
			"bash-lc":      "bash -lc " + quoted,
			"bash-ic":      "bash -ic " + quoted,
			"abs-bash-lc":  "/bin/bash -lc " + quoted,
			"zsh-c":        "zsh -c " + quoted,
			"sh-ec":        "sh -ec " + quoted,
			"sudo-bash-lc": "sudo bash -lc " + quoted,
			"env-bash-lc":  "env A=1 bash -lc " + quoted,
			"su-c":         "su -c " + quoted + " root",
			"sudo-i":       "sudo -i " + quoted,
			"find-exec":    "find . -maxdepth 1 -exec sh -c " + quoted + " \\;",
			"nested-twice": "bash -lc " + shellQuoteForTest("zsh -c "+quoted),
		}
		for name, command := range same {
			got := worstDefenseClawControl(DefenseClawControl(Analyze(defenseClawControlInput(defenseClawControlRow{Command: command})), command))
			if got != row.Want {
				t.Errorf("%s/%s: got %q, want %q", row.ID, name, got, row.Want)
			}
		}
		for _, program := range []string{"defenseclaw-gateway ", "defenseclaw "} {
			if !strings.HasPrefix(row.Command, program) {
				continue
			}
			for name, prefix := range map[string]string{"tilde": "~/.local/bin/", "home": "$HOME/.local/bin/", "quoted-home": `"$HOME/.local/bin/`} {
				command := prefix + row.Command
				if name == "quoted-home" {
					command = prefix + strings.TrimSuffix(program, " ") + `" ` + strings.TrimPrefix(row.Command, program)
				}
				got := worstDefenseClawControl(DefenseClawControl(Analyze(defenseClawControlInput(defenseClawControlRow{Command: command})), command))
				if got != row.Want {
					t.Errorf("%s/%s: got %q, want %q", row.ID, name, got, row.Want)
				}
			}
		}
		for name, command := range map[string]string{
			"ssh": "ssh localhost " + quoted,
		} {
			got := worstDefenseClawControl(DefenseClawControl(Analyze(defenseClawControlInput(defenseClawControlRow{Command: command})), command))
			if got != "unproven" {
				t.Errorf("%s/%s: got %q, want the unknown tier", row.ID, name, got)
			}
		}
		checked++
	}
	if checked < 40 {
		t.Fatalf("only %d proven rows were transformed; the corpus moved", checked)
	}
}

// TestDefenseClawControlDepthBound is GAP-0702: a call nested past the parse
// bounds that names DefenseClaw is read from the bash parse, not allowed: the
// command inside 12, 30 and 80 subshells is still the stop it is. Nesting the
// parse cut is otherwise the shared cap floor's reading.
func TestDefenseClawControlDepthBound(t *testing.T) {
	for _, depth := range []int{12, 30, 80} {
		command := strings.Repeat("( ", depth) + "defenseclaw-gateway stop" + strings.Repeat(" )", depth)
		got := worstDefenseClawControl(DefenseClawControl(Analyze(Input{Tool: "Bash", Command: command}), command))
		if got != "stop" {
			t.Errorf("%d nested subshells: got %q, want stop", depth, got)
		}
	}
	command := "bash -c 'ls'"
	if got := worstDefenseClawControl(DefenseClawControl(Analyze(Input{Tool: "Bash", Command: command}), command)); got != "" {
		t.Errorf("a call that does not name DefenseClaw: %q", got)
	}
}
