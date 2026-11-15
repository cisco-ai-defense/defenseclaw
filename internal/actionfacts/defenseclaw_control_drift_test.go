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
	"strings"
	"testing"
)

// TestDefenseClawServiceNamesFollowTheInstallers walks the installer and
// packaging code: every systemd unit, launchd plist and service, label or
// task name the installers define must be recognised as a DefenseClaw
// service, so a unit added later cannot fall outside the self-protection
// rules (GAP-0596). The names are read from the repository, not listed here.
func TestDefenseClawServiceNamesFollowTheInstallers(t *testing.T) {
	root := filepath.Join("..", "..")
	skipWithoutRepo(t, root)
	var seen int
	for _, dir := range []string{
		"packaging/systemd", "packaging/systemd/user", "packaging/launchd", "packaging/launchd-standalone",
		"packaging/launchd-standalone/agents",
	} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !regexp.MustCompile(`\.(service|socket|timer|path|plist)$`).MatchString(name) {
				continue
			}
			seen++
			if !IsDefenseClawServiceName(name) {
				t.Errorf("%s/%s is an installer unit that IsDefenseClawServiceName does not recognise", dir, name)
			}
		}
	}
	if seen < 20 {
		t.Fatalf("the walk found only %d installer units; the packaging layout moved", seen)
	}
	// Names the Go installers and the Windows module define.
	literal := regexp.MustCompile(`"((?:com\.cisco\.(?:secureclient\.)?)?defenseclaw[A-Za-z0-9._-]*|DefenseClaw[A-Za-z0-9_]*)"`)
	found := 0
	for _, file := range []string{
		"internal/enterpriseunix/services.go", "internal/winpath/enterprise_layout.go",
		"internal/managed/standalone_layout.go", "internal/openshell/launchagent_label.go",
	} {
		source := readRepoSource(t, filepath.Join(root, file))
		for _, match := range literal.FindAllStringSubmatch(source, -1) {
			name := match[1]
			// A program or a base label is checked as a service prefix.
			if strings.HasSuffix(name, ".") || strings.Contains(name, "_") && !strings.HasPrefix(name, "DefenseClaw") {
				continue
			}
			found++
			if !IsDefenseClawServiceName(name) {
				t.Errorf("%s names %q, which IsDefenseClawServiceName does not recognise", file, name)
			}
		}
	}
	if found < 8 {
		t.Fatalf("the scan found only %d installer names; the layout moved", found)
	}
	for _, program := range []string{"defenseclaw", "defenseclaw-gateway", "/usr/local/bin/defenseclaw", `C:\Program Files\DefenseClaw\bin\defenseclaw-gateway.exe`} {
		if defenseClawProgramName([]string{program}) == "" {
			t.Errorf("%q is a packaged program the control rules do not recognise", program)
		}
	}
}

// registeredCLICommands walks the Python CLI and the gateway CLI and returns
// every command and group name they register (click .command/.group with a
// name or a bare decorator over def NAME, cobra Use), with the files each
// `disable` is registered in.
func registeredCLICommands(t *testing.T, root string) (names map[string]bool, disableFiles map[string]bool) {
	t.Helper()
	named := regexp.MustCompile(`\.(?:command|group)\(\s*(?:name\s*=\s*)?"([a-z][a-z0-9_-]*)"`)
	bare := regexp.MustCompile(`(?m)^@[\w.]+\.(?:command|group)\(\)\s*\n(?:@[^\n]*\n)*(?:async\s+)?def\s+(\w+)\(`)
	cobra := regexp.MustCompile(`Use:\s+"([a-z][a-z0-9-]*)`)
	names, disableFiles = map[string]bool{}, map[string]bool{}
	scan := func(dir, ext string, patterns ...*regexp.Regexp) {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ext) || strings.HasSuffix(path, "_test.go") ||
				strings.Contains(path, "/tui/") || strings.Contains(path, "/tests/") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			for _, pattern := range patterns {
				for _, match := range pattern.FindAllStringSubmatch(normalizeSourceLF(data), -1) {
					name := strings.ReplaceAll(match[1], "_", "-")
					if pattern == bare {
						for _, suffix := range []string{"-command", "-cmd", "-group", "-grp"} {
							name = strings.TrimSuffix(name, suffix)
						}
					}
					names[name] = true
					if name == "disable" {
						disableFiles[filepath.Base(path)] = true
					}
				}
			}
			return nil
		})
	}
	scan("cli/defenseclaw", ".py", named, bare)
	scan("internal/cli", ".go", cobra)
	return names, disableFiles
}

// TestDefenseClawStopVerbsFollowTheCLI walks the registered CLI commands. A
// stop, disable, uninstall or teardown subcommand must be recognised as a
// control (GAP-0596), and a command name the rules have not classified is a
// new verb a developer must classify (GAP-0705: a new `halt` fails here until
// it is a stop verb, a read verb or recorded as neutral in
// testdata/defenseclaw_cli_commands.txt, the reviewed set of every other
// registered name). Set DEFENSECLAW_WRITE_CLI_SNAPSHOT=1 to rewrite the file.
func TestDefenseClawStopVerbsFollowTheCLI(t *testing.T) {
	root := filepath.Join("..", "..")
	skipWithoutRepo(t, root)
	names, disableFiles := registeredCLICommands(t, root)
	if len(names) < 50 {
		t.Fatalf("only %d command names found; the CLI layout moved", len(names))
	}
	// Every registered stop-class verb is decided and not read-only.
	for _, verb := range []string{"stop", "disable", "uninstall", "teardown", "remove-all", "kill", "shutdown"} {
		if !names[verb] {
			continue
		}
		kind, decided := judgeDefenseClawCLI([]string{"guardrail", verb}, "defenseclaw", false)
		if !decided || kind == "" {
			t.Errorf("registered subcommand %q is not treated as a control (kind %q, decided %v)", verb, kind, decided)
		}
	}
	// Every disable that turns a guardrail part off is registered in the
	// guardrail command file; a disable registered anywhere else (skill,
	// plugin, webhook, observability, discovery, routing, signatures) must
	// stay outside the guardrail group, or be classified here.
	for file := range disableFiles {
		switch file {
		case "cmd_guardrail.py":
		case "cmd_agent.py", "cmd_plugin.py", "cmd_skill.py", "cmd_mcp.py", "cmd_routing.py", "cmd_setup_galileo.py",
			"cmd_setup_observability.py", "cmd_setup_webhook.py", "cmd_setup.py":
			if kind, _ := judgeDefenseClawCLI([]string{"skill", "disable", "x"}, "defenseclaw", false); kind != "" {
				t.Errorf("a disable outside the guardrail group is judged %q", kind)
			}
		default:
			t.Errorf("a disable subcommand is registered in %s, a file this drift test has not classified: guardrail-group disables belong in defenseClawGuardGroups, others in the list above", file)
		}
	}
	known := map[string]bool{}
	for verb := range defenseClawStopVerbs {
		known[verb] = true
	}
	for verb := range defenseClawReadVerbs {
		known[verb] = true
	}
	for verb := range defenseClawRelaxVerbs {
		known[verb] = true
	}
	for group := range defenseClawGuardGroups {
		known[group] = true
	}
	// The Substrate commands, groups and verbs are classified by their own
	// tables (judgeDefenseClawSubstrate).
	for _, table := range []map[string]bool{
		defenseClawSubstrateCommands, defenseClawSubstrateGroups, defenseClawSubstrateReadVerbs,
		defenseClawSubstrateStopVerbs,
	} {
		for name := range table {
			known[name] = true
		}
	}
	known["disable"] = true
	snapshot := filepath.Join("testdata", "defenseclaw_cli_commands.txt")
	if os.Getenv("DEFENSECLAW_WRITE_CLI_SNAPSHOT") == "1" {
		var neutral []string
		for name := range names {
			if !known[name] {
				neutral = append(neutral, name)
			}
		}
		sort.Strings(neutral)
		if err := os.WriteFile(snapshot, []byte(strings.Join(neutral, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, name := range strings.Fields(readRepoSource(t, snapshot)) {
		known[name] = true
	}
	var unclassified []string
	for name := range names {
		if !known[name] {
			unclassified = append(unclassified, name)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("registered command names the control rules have not classified (add a stop verb to defenseClawStopVerbs, a read verb to defenseClawReadVerbs, or the name to testdata/defenseclaw_cli_commands.txt after review): %v", unclassified)
	}
}

// normalizeSourceLF turns CRLF into LF. A Windows checkout with
// core.autocrlf=true stores every source file with CRLF, and the source-reading
// tests match LF-anchored patterns (GAP-0936).
func normalizeSourceLF(data []byte) string {
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// readRepoSource reads a repository file for a source-reading test with CRLF
// normalised to LF. Every test in this package that reads repository source
// goes through it, so a CRLF checkout cannot break a pattern.
func readRepoSource(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return normalizeSourceLF(data)
}

// skipWithoutRepo skips a test that walks the repository when it runs from a
// copied test binary (the native Windows runs) without the source tree.
func skipWithoutRepo(t *testing.T, root string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("no repository tree next to the test binary")
	}
}
