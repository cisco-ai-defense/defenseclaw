// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type defenseClawControlRow struct {
	ID      string `json:"id"`
	Dialect string `json:"dialect"`
	Command string `json:"command"`
	Want    string `json:"want"`
}

func loadDefenseClawControlRows(t *testing.T) []defenseClawControlRow {
	t.Helper()
	file, err := os.Open("testdata/defenseclaw_control.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var rows []defenseClawControlRow
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var row defenseClawControlRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	return rows
}

// TestDefenseClawControlCorpusIDsAreUnique keeps every row id of the control
// corpus unique and non-empty, so a failure message names one row and a corpus
// diff shows one row per id. Two substrate port rows once reused sub18b-45 and
// sub18b-46 (GAP-1013); the loader keeps a list, so all four still ran and
// nothing failed.
func TestDefenseClawControlCorpusIDsAreUnique(t *testing.T) {
	rows := loadDefenseClawControlRows(t)
	seen := map[string]int{}
	for i, row := range rows {
		if row.ID == "" {
			t.Errorf("control corpus row %d has no id (command %q)", i+1, row.Command)
			continue
		}
		if first, dup := seen[row.ID]; dup {
			t.Errorf("control corpus id %q is on rows %d and %d (commands %q, %q)", row.ID, first, i+1,
				rows[first-1].Command, row.Command)
			continue
		}
		seen[row.ID] = i + 1
	}
}

func defenseClawControlInput(row defenseClawControlRow) Input {
	input := Input{Tool: "Bash", Command: row.Command, CWD: "/home/u/proj", ActiveHome: "/home/u"}
	switch row.Dialect {
	case "powershell":
		input.Tool = "PowerShell"
		input.DialectHint = DialectPowerShell
		input.CWD = `C:\Users\u\proj`
		input.ActiveHome = `C:\Users\u`
	case "cmd":
		input.DialectHint = DialectCMD
		input.CWD = `C:\Users\u\proj`
		input.ActiveHome = `C:\Users\u`
	}
	return input
}

// worst is the strongest kind of a call's findings: a proven kind outranks
// the unproven one.
func worstDefenseClawControl(facts []DefenseClawControlFact) string {
	best := ""
	for _, fact := range facts {
		if fact.Proven {
			return string(fact.Kind)
		}
		best = string(fact.Kind)
	}
	return best
}

func TestDefenseClawControlRows(t *testing.T) {
	for _, row := range loadDefenseClawControlRows(t) {
		t.Run(row.ID, func(t *testing.T) {
			got := worstDefenseClawControl(DefenseClawControl(Analyze(defenseClawControlInput(row)), row.Command))
			if got != row.Want {
				t.Fatalf("%s: got %q, want %q", row.ID, got, row.Want)
			}
		})
	}
}

func TestIsDefenseClawServiceName(t *testing.T) {
	for _, name := range []string{
		"defenseclaw-gateway", "defenseclaw-gateway.service", "DefenseClawGateway",
		"DefenseClawCertGuardian_0123456789", "com.cisco.defenseclaw.gateway",
		"com.cisco.secureclient.defenseclaw.hook-guardian",
		"system/com.cisco.defenseclaw.gateway", "/Library/LaunchDaemons/com.cisco.defenseclaw.apply.plist",
		"defenseclaw-hook-guardian.timer",
	} {
		if !IsDefenseClawServiceName(name) {
			t.Errorf("%q is a DefenseClaw service name", name)
		}
	}
	for _, name := range []string{"", "nginx", "myapp.service", "com.apple.defense", "claw"} {
		if IsDefenseClawServiceName(name) {
			t.Errorf("%q is not a DefenseClaw service name", name)
		}
	}
	_ = strings.ToLower
}
