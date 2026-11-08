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
	"encoding/json"
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
//
// The earlier folder is DefenseClaw's only when the install home or the list
// config set data_dir keeps in the install home names it: a marked approval
// that names any other folder, present or absent, keeps the refusal.
type movedStoreFixture struct {
	root, home, allowlist string
}

// newMovedStoreFixture makes <root>/.defenseclaw the install home, the default
// data_dir of the first Setup.
func newMovedStoreFixture(t *testing.T) movedStoreFixture {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	home := filepath.Join(root, ".defenseclaw")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	return movedStoreFixture{root: root, home: home, allowlist: filepath.Join(root, ".hermes", hermesAllowlistFileName)}
}

// writeEarlierDataDirList writes the list config set data_dir keeps in the
// install home.
func writeEarlierDataDirList(t *testing.T, home string, mode os.FileMode, folders ...string) {
	t.Helper()
	body, err := json.Marshal(map[string][]string{"folders": folders})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, hermesEarlierDataDirsFile)
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func (f movedStoreFixture) listEarlier(t *testing.T, dirs ...string) {
	t.Helper()
	folders := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		folders = append(folders, filepath.Join(f.root, dir))
	}
	writeEarlierDataDirList(t, f.home, 0o600, folders...)
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
	f.listEarlier(t, "state")
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
	f.listEarlier(t, filepath.Join("state", "old"))
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

// A marked approval that names a hooks/hermes-hook.sh below a folder that is
// neither the install home nor in the list is not shown to be DefenseClaw's,
// whether the path is absent or holds a copy of the generated script.
func TestSetupKeepsTheRefusalForAFolderThatIsNotAnEarlierDataDir(t *testing.T) {
	f := newMovedStoreFixture(t)
	f.generatedScript(t, "copied")
	f.listEarlier(t, "state0")
	other := filepath.Join(f.root, "listed-but-not-ours")
	script := filepath.Join(other, "hooks", hermesHookScriptName)
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec /usr/local/bin/user-hook\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeEarlierDataDirList(t, f.home, 0o600, filepath.Join(f.root, "state0"), other)
	cases := map[string]string{
		"an absent sibling folder":                             f.command("stranger"),
		"an absent folder below the list\x27s folder":          f.command(filepath.Join("state0", "inner")),
		"a folder that holds a copy of the generated script":   f.command("copied"),
		"a listed folder whose script is not DefenseClaw\x27s": f.command("listed-but-not-ours"),
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

// The list proves a folder only when it is a regular file only the account
// can change; a list another account can read, change or replace with a link
// names nothing, and so does a malformed one.
func TestAnEarlierDataDirListThatIsNotPrivateNamesNothing(t *testing.T) {
	f := newMovedStoreFixture(t)
	f.generatedScript(t, "state0")
	command := f.command("state")
	listed := filepath.Join(f.root, "state0")
	list := filepath.Join(f.home, hermesEarlierDataDirsFile)
	refused := func(label string) {
		t.Helper()
		f.write(t, f.command("state0"))
		if err := checkHermesAllowlistRepairable(f.allowlist, command); err == nil || !strings.Contains(err.Error(), "tampered DefenseClaw command") {
			t.Errorf("%s: repair = %v, want the tampered-command refusal", label, err)
		}
	}
	writeEarlierDataDirList(t, f.home, 0o600, listed)
	f.write(t, f.command("state0"))
	if err := checkHermesAllowlistRepairable(f.allowlist, command); err != nil {
		t.Fatalf("the private list was refused: %v", err)
	}
	writeEarlierDataDirList(t, f.home, 0o644, listed)
	refused("a list other accounts can read")
	if err := os.Remove(list); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(f.root, "real-list.json")
	writeEarlierDataDirList(t, f.root, 0o600, listed)
	if err := os.Rename(filepath.Join(f.root, hermesEarlierDataDirsFile), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, list); err != nil {
		t.Fatal(err)
	}
	refused("a list that is a link")
	if err := os.Remove(list); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(list, []byte(`{"folders": "not a list"`), 0o600); err != nil {
		t.Fatal(err)
	}
	refused("a malformed list")
	if err := os.WriteFile(list, []byte(`{"folders": ["relative/state0", 7]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	refused("a list of relative paths")
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
	// The install home is ~/.defenseclaw: Setup runs with the data directory
	// as DEFENSECLAW_HOME, as the Hermes admission fixture sets it.
	t.Setenv("HOME", dir)
	home := filepath.Join(dir, ".defenseclaw")
	previousOverride := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previousOverride })
	allowlist := filepath.Join(hermesHome, hermesAllowlistFileName)

	conn := NewHermesConnector()
	var opts SetupOpts
	var earlier []string
	for _, name := range []string{".defenseclaw", "state", "state2"} {
		if name != ".defenseclaw" {
			// config set data_dir lists the folder it leaves; the install home
			// is never listed.
			writeEarlierDataDirList(t, home, 0o600, earlier...)
		}
		if name == "state" {
			earlier = append(earlier, filepath.Join(dir, name))
		}
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
	t.Setenv("HOME", dir)
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
