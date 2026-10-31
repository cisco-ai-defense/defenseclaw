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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// rel-1-0-2 GAP-0642: a true move of a home (usermod -d -m) carries the
// Hermes allowlist approvals DefenseClaw wrote, and they still name the hook
// script below the old home. Teardown in the new home refused them as a
// tampered DefenseClaw command on every run, so the re-homed cleanup row
// never completed. The approvals for the recorded earlier home are
// DefenseClaw's; any other command on a marked entry is still refused.
func writeRehomedHermesAllowlist(t *testing.T, path string, commands map[string]string) {
	t.Helper()
	var approvals []interface{}
	for event, command := range commands {
		approvals = append(approvals, map[string]interface{}{"event": event, "command": command, hermesAllowlistOwnerField: true})
	}
	approvals = append(approvals, map[string]interface{}{"event": "pre_tool_call", "command": "/usr/local/bin/user-hook"})
	body, err := json.MarshalIndent(map[string]interface{}{"approvals": approvals}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rehomedHermesFixture(t *testing.T) (oldHome, newHome, allowlist, command, oldCommand string) {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	oldHome, newHome = filepath.Join(root, "home", "r106fx"), filepath.Join(root, "home", "r106fx2")
	if err := os.MkdirAll(newHome, 0o700); err != nil {
		t.Fatal(err)
	}
	allowlist = filepath.Join(newHome, ".hermes", hermesAllowlistFileName)
	command = hermesConfiguredHookCommand(filepath.Join(newHome, ".defenseclaw", "hooks", hermesHookScriptName), "")
	oldCommand = hermesConfiguredHookCommand(filepath.Join(oldHome, ".defenseclaw", "hooks", hermesHookScriptName), "")
	return oldHome, newHome, allowlist, command, oldCommand
}

func requireOnlyUserApproval(t *testing.T, allowlist string) {
	t.Helper()
	document, err := readHermesAllowlist(allowlist)
	if err != nil {
		t.Fatal(err)
	}
	approvals := document["approvals"].([]interface{})
	if len(approvals) != 1 || approvals[0].(map[string]interface{})["command"] != "/usr/local/bin/user-hook" {
		t.Fatalf("after the re-homed cleanup the allowlist holds %v, want only the user's own approval", approvals)
	}
}

func TestRehomedCleanupRemovesTheApprovalsOfTheRecordedHome(t *testing.T) {
	oldHome, newHome, allowlist, command, oldCommand := rehomedHermesFixture(t)
	commands := map[string]string{}
	for event := range hermesHookEventSet() {
		commands[event] = oldCommand
	}
	writeRehomedHermesAllowlist(t, allowlist, commands)
	defer BindManagedBackupPreviousHome(oldHome)()
	err := WithUserHomeDir(newHome, func() error { return removeHermesOwnedApprovals(allowlist, command, nil, true) })
	if err != nil {
		t.Fatalf("re-homed cleanup refused DefenseClaw's approvals of the recorded home: %v", err)
	}
	requireOnlyUserApproval(t, allowlist)
}

func TestRehomedCleanupFindsTheEarlierHomeInTheReceipt(t *testing.T) {
	oldHome, newHome, allowlist, command, oldCommand := rehomedHermesFixture(t)
	commands := map[string]string{}
	for event := range hermesHookEventSet() {
		commands[event] = oldCommand
	}
	writeRehomedHermesAllowlist(t, allowlist, commands)
	// No bound previous home: the row already names the new home. The
	// receipt Setup wrote still records where the file was captured.
	receipt := &managedFileBackup{Connector: "hermes", LogicalName: hermesAllowlistLogicalName,
		Path: filepath.Join(oldHome, ".hermes", hermesAllowlistFileName), Existed: false}
	err := WithUserHomeDir(newHome, func() error { return removeHermesOwnedApprovals(allowlist, command, receipt, true) })
	if err != nil {
		t.Fatalf("cleanup refused DefenseClaw's approvals of the home its receipt records: %v", err)
	}
	requireOnlyUserApproval(t, allowlist)
}

func TestRehomedCleanupStillRefusesAnotherCommandOnAMarkedEntry(t *testing.T) {
	oldHome, newHome, allowlist, command, _ := rehomedHermesFixture(t)
	other := hermesConfiguredHookCommand(filepath.Join(filepath.Dir(oldHome), "elsewhere", ".defenseclaw", "hooks", hermesHookScriptName), "")
	commands := map[string]string{}
	for event := range hermesHookEventSet() {
		commands[event] = other
		break
	}
	writeRehomedHermesAllowlist(t, allowlist, commands)
	defer BindManagedBackupPreviousHome(oldHome)()
	err := WithUserHomeDir(newHome, func() error { return removeHermesOwnedApprovals(allowlist, command, nil, true) })
	if err == nil || !strings.Contains(err.Error(), "tampered DefenseClaw command") {
		t.Fatalf("a marked entry naming a path outside the recorded homes = %v, want the tampered-command refusal", err)
	}
}

func TestDifferingPathRoots(t *testing.T) {
	for _, tc := range []struct{ captured, current, old, new string }{
		{"/home/a/.hermes/x.json", "/home/a2/.hermes/x.json", "/home/a", "/home/a2"},
		{"/home/a/.hermes/x.json", "/home/a/.hermes/x.json", "", ""},
		{"/home/a/.hermes/x.json", "/srv/users/a/.hermes/x.json", "/home", "/srv/users"},
		{"/a/x.json", "/b/y.json", "/a/x.json", "/b/y.json"},
	} {
		old, current := differingPathRoots(tc.captured, tc.current)
		if old != tc.old || current != tc.new {
			t.Errorf("differingPathRoots(%q, %q) = %q, %q; want %q, %q", tc.captured, tc.current, old, current, tc.old, tc.new)
		}
	}
}
