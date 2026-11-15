// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// defenseClawNeutralConfigRoots are the sections of config.yaml whose change
// is not a change to the guard: telemetry sinks, routing, webhooks,
// notifications, the update channel and AI discovery (GAP-0753). Reviewed
// with defenseClawGuardConfigRoots: every section of the Config schema is in
// exactly one of the two.
var defenseClawNeutralConfigRoots = map[string]bool{
	"observability": true, "webhooks": true, "notifications": true, "routing": true,
	"update": true, "ai_discovery": true,
}

// TestDefenseClawConfigRootsAreClassified reads the Config schema and requires
// each top-level section to be classified as a guard section or a neutral one.
// A new section fails here until a developer decides which it is.
func TestDefenseClawConfigRootsAreClassified(t *testing.T) {
	root := filepath.Join("..", "..")
	skipWithoutRepo(t, root)
	data, err := os.ReadFile(filepath.Join(root, "internal", "config", "config.go"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)\ntype Config struct \{.*?\n\}\n`).Find(data)
	if block == nil {
		t.Fatal("the Config struct moved; update this test")
	}
	roots := map[string]bool{}
	for _, match := range regexp.MustCompile("yaml:\"([a-z][a-z0-9_]*)").FindAllSubmatch(block, -1) {
		roots[string(match[1])] = true
	}
	if len(roots) < 30 {
		t.Fatalf("only %d config sections found; the schema layout moved", len(roots))
	}
	var unclassified, both, stale []string
	for name := range roots {
		guard, neutral := defenseClawGuardConfigRoots[name], defenseClawNeutralConfigRoots[name]
		switch {
		case guard && neutral:
			both = append(both, name)
		case !guard && !neutral:
			unclassified = append(unclassified, name)
		}
	}
	for name := range defenseClawGuardConfigRoots {
		if !roots[name] {
			stale = append(stale, name)
		}
	}
	for name := range defenseClawNeutralConfigRoots {
		if !roots[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(unclassified)
	sort.Strings(both)
	sort.Strings(stale)
	if len(unclassified) > 0 {
		t.Errorf("config sections not classified for `config set` (add to defenseClawGuardConfigRoots or defenseClawNeutralConfigRoots): %v", unclassified)
	}
	if len(both) > 0 {
		t.Errorf("config sections classified both guard and neutral: %v", both)
	}
	if len(stale) > 0 {
		t.Errorf("classified config sections that the schema no longer has: %v", stale)
	}
}

// TestDefenseClawExtensionGroupsAreRegisteredGroups pins the groups whose
// `uninstall` removes an extension (GAP-0753): each is a command group the CLI
// registers, so a rename does not silently turn `plugin uninstall` back into
// the product uninstall.
func TestDefenseClawExtensionGroupsAreRegisteredGroups(t *testing.T) {
	root := filepath.Join("..", "..")
	skipWithoutRepo(t, root)
	names, _ := registeredCLICommands(t, root)
	for group := range defenseClawExtensionGroups {
		if !names[group] {
			t.Errorf("%q is listed as an extension group but the CLI registers no such command", group)
		}
	}
	if kind, decided := judgeDefenseClawCLI([]string{"uninstall"}, "defenseclaw", false); kind != DefenseClawControlUninstall || !decided {
		t.Errorf("the product uninstall is judged %q (decided %v)", kind, decided)
	}
	if kind, decided := judgeDefenseClawCLI([]string{"guardrail", "uninstall"}, "defenseclaw", false); kind != DefenseClawControlUninstall || !decided {
		t.Errorf("a guardrail uninstall is judged %q (decided %v)", kind, decided)
	}
}
