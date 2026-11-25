// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1759 (3), RV-W111G: the GAP-1714 prune match takes the exact per-event
// Codex commands this release renders or owns. Its negative side had only an
// unrelated operator hook; these are near misses of the DefenseClaw forms (an
// extra argument after a rendered per-event command, the launcher form from
// another binary path, the launcher form with an extra argument) that
// prune-orphans must not report, because none of them is a command
// DefenseClaw wrote.
func TestGAP1759OrphanedCodexNearMissCommandsAreNotReported(t *testing.T) {
	home := testenv.PrivateTempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	contracts := builtinHookContracts["codex"]
	if len(contracts) == 0 {
		t.Fatal("no built-in Codex hook contract")
	}
	contract := contracts[len(contracts)-1]
	event := contract.Events[0]
	rendered := windowsCodexHookCommandForEvent(event, contract.ContractID)
	label := codexHookEventKeyLabel(event)
	path := codexConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")}
	conn := NewCodexConnector()
	write := func(command string) {
		t.Helper()
		if strings.Contains(command, "'") || strings.Contains(command, "\n") {
			t.Fatalf("fixture: %q cannot be a TOML literal string", command)
		}
		body := "[[hooks." + label + "]]\n[[hooks." + label + ".hooks]]\ntype = \"command\"\ncommand = '" + command + "'\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The exact rendered command is reported (the GAP-1714 positive side),
	// so the near misses below are judged by the same matcher.
	write(rendered)
	if found, err := orphanedHookConfigPathsFor("windows", conn, opts); err != nil || !slices.Contains(found, path) {
		t.Fatalf("fixture: the rendered per-event command is not reported: found %v, err %v", found, err)
	}
	for name, command := range map[string]string{
		"rendered command with an extra argument": rendered + " -Verbose",
		"launcher from another binary path":       `C:\Tools\defenseclaw\defenseclaw.exe hook --connector codex`,
		"launcher with an extra argument":         `C:\Tools\defenseclaw\defenseclaw.exe hook --connector codex --event pre`,
	} {
		write(command)
		found, err := orphanedHookConfigPathsFor("windows", conn, opts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if slices.Contains(found, path) {
			t.Fatalf("%s: prune-orphans reported %q, which DefenseClaw did not write", name, command)
		}
	}
}
