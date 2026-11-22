// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// defenseClawNeutralConfigRoots are the sections of config.yaml whose change
// is not a change to the guard: routing, webhooks, notifications, the update
// channel and AI discovery (GAP-0753). observability is a guard section (the
// audit and OTLP export are evidence). Reviewed with
// defenseClawGuardConfigRoots: every section of the Config schema is in
// exactly one of the two.
var defenseClawNeutralConfigRoots = map[string]bool{
	"webhooks": true, "notifications": true, "routing": true,
	"update": true, "ai_discovery": true,
}

// TestDefenseClawConfigRootsAreClassified reads the Config schema and requires
// each top-level section to be classified as a guard section or a neutral one.
// A new section fails here until a developer decides which it is.
func TestDefenseClawConfigRootsAreClassified(t *testing.T) {
	root := filepath.Join("..", "..")
	skipWithoutRepo(t, root)
	source := readRepoSource(t, filepath.Join(root, "internal", "config", "config.go"))
	block := regexp.MustCompile(`(?s)\ntype Config struct \{.*?\n\}\n`).FindString(source)
	if block == "" {
		t.Fatal("the Config struct moved; update this test")
	}
	roots := map[string]bool{}
	for _, match := range regexp.MustCompile("yaml:\"([a-z][a-z0-9_]*)").FindAllStringSubmatch(block, -1) {
		roots[match[1]] = true
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

// TestDefenseClawControlDataHeredocWithAnUnresolvedCommand is GAP-0755: a task
// brief written with cat > FILE <<'TASK' names DefenseClaw in prose, and the
// call runs a command later that the parse cannot resolve (a script word built
// from variables). The here-document feeds cat, so it is data: the call names
// the product in no command, and the unresolved command is not a DefenseClaw
// reading. A here-document that feeds a shell keeps its reading.
func TestDefenseClawControlDataHeredocWithAnUnresolvedCommand(t *testing.T) {
	prose := "Notes on DefenseClaw: the <DefenseClawDropInName> file, the defenseclaw-dev hosts.\n" +
		"Do not run defenseclaw-gateway stop in this sandbox; a run of defenseclaw guardrail disable is not allowed.\n" +
		"defenseclaw-gateway stop\n"
	call := func(consumer string) string {
		return "D=/home/u/work; N=brief; mkdir -p $D; cd $D\ncat > $N.md <<'TASK'\n" + prose + "TASK\n" +
			consumer + "\nsleep 5; ls $D | grep $N"
	}
	input := func(text string) Input {
		return Input{Tool: "Bash", Command: text, CWD: "/home/u/work", ActiveHome: "/home/u"}
	}
	for name, consumer := range map[string]string{
		"a script word built from variables": `nohup bash -c "$RUN" '$D/$N.out' > /dev/null 2>&1 &`,
		"a program in a variable":            `"$TOOL" --prompt-file "$D/$N.md" --out "$D/$N.out"`,
	} {
		text := call(consumer)
		if got := worstDefenseClawControl(DefenseClawControl(Analyze(input(text)), text)); got != "" {
			t.Errorf("%s: a data here-document made the call %q", name, got)
		}
	}
	// The same prose fed to a shell is a script, and says what it says.
	script := "bash <<'TASK'\n" + prose + "TASK\n"
	if got := worstDefenseClawControl(DefenseClawControl(Analyze(input(script)), script)); got == "" {
		t.Errorf("a here-document that feeds a shell was not read")
	}
	// A filter in front of a shell passes the document on.
	piped := "cat <<'TASK' | sh\n" + prose + "TASK\n"
	if got := worstDefenseClawControl(DefenseClawControl(Analyze(input(piped)), piped)); got == "" {
		t.Errorf("a here-document piped through cat into a shell was not read")
	}
}
