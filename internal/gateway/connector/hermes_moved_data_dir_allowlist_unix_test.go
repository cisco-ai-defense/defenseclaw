// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0914: defenseclaw config set data_dir copies the connector records and
// leaves the Hermes allowlist as it was, so the approvals Setup wrote still
// name hooks/hermes-hook.sh below the earlier data directory. Setup read its
// own approval as a tampered command and refused the restart and the repeat
// setup. The approval of any earlier data directory is DefenseClaw's; any
// other command on a marked entry is still refused.
type movedStoreFixture struct {
	root, allowlist string
}

func newMovedStoreFixture(t *testing.T) movedStoreFixture {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	return movedStoreFixture{root: root, allowlist: filepath.Join(root, ".hermes", hermesAllowlistFileName)}
}

func (f movedStoreFixture) command(dir string) string {
	return hermesConfiguredHookCommand(filepath.Join(f.root, dir, "hooks", hermesHookScriptName), "")
}

// generatedScript leaves the hook script Setup generated in the folder.
func (f movedStoreFixture) generatedScript(t *testing.T, dir string) {
	t.Helper()
	script := filepath.Join(f.root, dir, "hooks", hermesHookScriptName)
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+hookSchemaVersionMarker+"1\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func (f movedStoreFixture) write(t *testing.T, command string) {
	t.Helper()
	commands := map[string]string{}
	for event := range hermesHookEventSet() {
		commands[event] = command
	}
	writeRehomedHermesAllowlist(t, f.allowlist, commands)
}

func requireApprovalsNaming(t *testing.T, allowlist, want string) {
	t.Helper()
	document, err := readHermesAllowlist(allowlist)
	if err != nil {
		t.Fatal(err)
	}
	owned := 0
	for _, raw := range document["approvals"].([]interface{}) {
		entry := raw.(map[string]interface{})
		if marked, _ := entry[hermesAllowlistOwnerField].(bool); !marked {
			continue
		}
		owned++
		if entry["command"] != want {
			t.Fatalf("DefenseClaw approval names %v, want %s", entry["command"], want)
		}
	}
	if owned != len(hermesHookEventSet()) {
		t.Fatalf("%d DefenseClaw approvals, want one per event", owned)
	}
}

func TestSetupRewritesTheApprovalOfAnEarlierDataDir(t *testing.T) {
	f := newMovedStoreFixture(t)
	f.generatedScript(t, ".defenseclaw")
	f.write(t, f.command(".defenseclaw"))
	command := f.command("state")
	if err := checkHermesAllowlistRepairable(f.allowlist, command); err != nil {
		t.Fatalf("repair refused DefenseClaw's approval of the earlier data_dir: %v", err)
	}
	if err := patchHermesAllowlist(f.allowlist, command, strings.Trim(command, "'")); err != nil {
		t.Fatal(err)
	}
	requireApprovalsNaming(t, f.allowlist, command)
	requireUserApprovalKept(t, f.allowlist)
}

func TestSetupRewritesTheApprovalAfterASecondDataDirMove(t *testing.T) {
	f := newMovedStoreFixture(t)
	f.generatedScript(t, ".defenseclaw")
	f.generatedScript(t, "state")
	for _, from := range []string{"state", ".defenseclaw"} {
		f.write(t, f.command(from))
		command := f.command("state2")
		if err := patchHermesAllowlist(f.allowlist, command, strings.Trim(command, "'")); err != nil {
			t.Fatalf("second move from %s: %v", from, err)
		}
		requireApprovalsNaming(t, f.allowlist, command)
	}
}

func TestSetupRewritesTheApprovalWhenTheEarlierDataDirIsInsideTheNewOne(t *testing.T) {
	f := newMovedStoreFixture(t)
	f.write(t, f.command(filepath.Join("state", "old")))
	command := f.command("state")
	if err := patchHermesAllowlist(f.allowlist, command, strings.Trim(command, "'")); err != nil {
		t.Fatalf("a data_dir that holds the earlier one: %v", err)
	}
	requireApprovalsNaming(t, f.allowlist, command)
}

func TestTeardownRemovesTheApprovalOfAnEarlierDataDir(t *testing.T) {
	f := newMovedStoreFixture(t)
	f.generatedScript(t, ".defenseclaw")
	f.write(t, f.command(".defenseclaw"))
	if err := removeHermesOwnedApprovals(f.allowlist, f.command("state"), nil, true); err != nil {
		t.Fatalf("cleanup refused DefenseClaw's approval of the earlier data_dir: %v", err)
	}
	requireOnlyUserApproval(t, f.allowlist)
}

func TestSetupKeepsTheRefusalForACommandThatIsNotDefenseClawsOnAMarkedEntry(t *testing.T) {
	f := newMovedStoreFixture(t)
	notOurs := f.command("evil")
	script := filepath.Join(f.root, "evil", "hooks", hermesHookScriptName)
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec /usr/local/bin/user-hook\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"a script that is not DefenseClaw's":         notOurs,
		"another script name below a hooks folder":   hermesConfiguredHookCommand(filepath.Join(f.root, "state0", "hooks", "other-hook.sh"), ""),
		"the script name outside a hooks folder":     hermesConfiguredHookCommand(filepath.Join(f.root, "state0", "bin", hermesHookScriptName), ""),
		"a relative path":                            "state0/hooks/" + hermesHookScriptName,
		"the script with an argument":                f.command("state0") + " --extra",
		"a program that is not a hook script at all": "/usr/local/bin/user-hook",
		"the script name in the root hooks folder":   hermesConfiguredHookCommand("/hooks/"+hermesHookScriptName, ""),
		"the bare form against the quoted form":      strings.Trim(f.command("state0"), "\x27"),
	}
	command := f.command("state")
	for name, entry := range cases {
		f.write(t, entry)
		for label, run := range map[string]func() error{
			"repair":   func() error { return checkHermesAllowlistRepairable(f.allowlist, command) },
			"teardown": func() error { return removeHermesOwnedApprovals(f.allowlist, command, nil, true) },
		} {
			if err := run(); err == nil || !strings.Contains(err.Error(), "tampered DefenseClaw command") {
				t.Errorf("%s of a marked entry naming %s = %v, want the tampered-command refusal", label, name, err)
			}
		}
	}
}

func requireUserApprovalKept(t *testing.T, allowlist string) {
	t.Helper()
	document, err := readHermesAllowlist(allowlist)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range document["approvals"].([]interface{}) {
		if raw.(map[string]interface{})["command"] == "/usr/local/bin/user-hook" {
			return
		}
	}
	t.Fatalf("the user's own approval was removed: %v", document["approvals"])
}

// The whole path of the report: Setup in one data directory, then again after
// each move of the data directory. The advised restart and the repeat setup
// both ran this and failed on the approvals the earlier Setup wrote.
func TestSetupAfterEachDataDirMoveRewritesItsOwnApprovals(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	hermesHome := filepath.Join(dir, ".hermes")
	t.Setenv("HERMES_HOME", hermesHome)
	previousOverride := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previousOverride })
	allowlist := filepath.Join(hermesHome, hermesAllowlistFileName)

	conn := NewHermesConnector()
	var opts SetupOpts
	for _, name := range []string{".defenseclaw", "state", "state2"} {
		opts = prepareHermesSetupAdmissionFixture(t, SetupOpts{
			DataDir: filepath.Join(dir, name), APIAddr: "127.0.0.1:18970", APIToken: "tok-test",
		})
		if err := conn.Setup(context.Background(), opts); err != nil {
			t.Fatalf("Setup in %s: %v", name, err)
		}
		requireApprovalsNaming(t, allowlist, hermesConfiguredHookCommand(conn.hookCommand(opts), opts.HookExecutable))
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown after the moves: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean after the moves: %v", err)
	}
}

// Cleanup after a move that was never followed by a Setup: the approvals name
// the earlier directory and the data directory is the new one.
func TestTeardownAfterADataDirMoveWithoutANewSetup(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	t.Setenv("HERMES_HOME", filepath.Join(dir, ".hermes"))
	previousOverride := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previousOverride })

	conn := NewHermesConnector()
	first := prepareHermesSetupAdmissionFixture(t, SetupOpts{DataDir: filepath.Join(dir, ".defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"})
	if err := conn.Setup(context.Background(), first); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	moved := first
	moved.DataDir = filepath.Join(dir, "state")
	if err := conn.Teardown(context.Background(), moved); err != nil {
		t.Fatalf("Teardown in the moved data directory: %v", err)
	}
	if err := conn.VerifyClean(moved); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}
