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

// GAP-1714: the rollback prune (connector prune-orphans) found a Windows
// Codex config.toml only by the plain `hook --connector codex` launcher
// command, but per-user Codex registers each event with its own exact form
// (the cmd.exe direct start, or the PowerShell -EncodedCommand guarded or
// answering bridge), so after a rollback to a release whose data folder never
// set Codex up the prune reported nothing and the 11 Codex hook tables stayed,
// running a launcher the later uninstall deleted. The prune now takes every
// exact per-user command this release renders or owns (the ones teardown
// removes). Fails on f36b28f9db: no file was reported.
func TestGAP1714OrphanedCodexWindowsPerEventFormsAreFound(t *testing.T) {
	home := testenv.PrivateTempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	contracts := builtinHookContracts["codex"]
	if len(contracts) == 0 {
		t.Fatal("no built-in Codex hook contract")
	}
	contract := contracts[len(contracts)-1]
	var body strings.Builder
	for _, event := range contract.Events {
		command := windowsCodexHookCommandForEvent(event, contract.ContractID)
		if strings.Contains(command, "'") || strings.Contains(command, "\n") {
			t.Fatalf("fixture: command for %s cannot be a TOML literal string: %q", event, command)
		}
		if hookCommandMatches(command, nativeHookFlag+"codex") {
			t.Fatalf("fixture: %s renders the plain launcher command; this test checks nothing", event)
		}
		label := codexHookEventKeyLabel(event)
		body.WriteString("[[hooks." + label + "]]\n[[hooks." + label + ".hooks]]\ntype = \"command\"\ncommand = '" + command + "'\n\n")
	}
	path := codexConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")}
	conn := NewCodexConnector()
	if !slices.Contains(HookConfigPathsForConnector(conn, opts), path) {
		t.Fatalf("fixture: %s is not a Codex hook config path (%v)", path, HookConfigPathsForConnector(conn, opts))
	}

	found, err := orphanedHookConfigPathsFor("windows", conn, opts)
	if err != nil {
		t.Fatalf("orphanedHookConfigPathsFor: %v", err)
	}
	if !slices.Contains(found, path) {
		t.Fatalf("GAP-1714: the Windows Codex per-event hooks in %s were not reported as orphans (found %v)", path, found)
	}

	// An operator's own Codex hook alone is never reported.
	operator := "[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\Tools\\audit.exe --event pre'\n"
	if err := os.WriteFile(path, []byte(operator), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err = orphanedHookConfigPathsFor("windows", conn, opts)
	if err != nil || slices.Contains(found, path) {
		t.Fatalf("operator-only Codex config: found %v, err %v; want it left alone", found, err)
	}
}
