// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path/filepath"
	"regexp"
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
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range literal.FindAllStringSubmatch(string(data), -1) {
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

// TestDefenseClawStopVerbsFollowTheCLI walks the registered CLI commands: a
// stop, disable, uninstall or teardown subcommand in the Python CLI or the
// gateway must be recognised as a control (GAP-0596). A new one fails here
// until it is.
func TestDefenseClawStopVerbsFollowTheCLI(t *testing.T) {
	root := filepath.Join("..", "..")
	skipWithoutRepo(t, root)
	click := regexp.MustCompile(`\.command\(\s*"(stop|disable|uninstall|teardown|remove-all|shutdown|kill)"`)
	cobra := regexp.MustCompile(`Use:\s+"(stop|disable|uninstall|teardown|remove-all|shutdown|kill)\b`)
	seen := map[string]bool{}
	scan := func(dir, ext string, re *regexp.Regexp) {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ext) || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			for _, match := range re.FindAllStringSubmatch(string(data), -1) {
				seen[match[1]] = true
			}
			return nil
		})
	}
	scan("cli/defenseclaw", ".py", click)
	scan("internal/cli", ".go", cobra)
	if len(seen) == 0 {
		t.Fatal("no stop-class subcommands found; the CLI layout moved")
	}
	for verb := range seen {
		args := []string{"guardrail", verb}
		if verb == "disable" || verb == "stop" || verb == "uninstall" || verb == "teardown" || verb == "remove-all" || verb == "kill" || verb == "shutdown" {
			if _, decided := judgeDefenseClawCLI(args, "defenseclaw", false); !decided {
				t.Errorf("registered subcommand %q is not decided by the control rules", verb)
			}
			kind, _ := judgeDefenseClawCLI(args, "defenseclaw", false)
			if kind == "" {
				t.Errorf("registered subcommand %q is treated as read-only", verb)
			}
		}
	}
}

// skipWithoutRepo skips a test that walks the repository when it runs from a
// copied test binary (the native Windows runs) without the source tree.
func skipWithoutRepo(t *testing.T, root string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("no repository tree next to the test binary")
	}
}
