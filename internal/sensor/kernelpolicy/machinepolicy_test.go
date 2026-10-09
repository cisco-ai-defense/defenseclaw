// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Machine-policy enrollment (SPEC-TETRAGON-UX B1, OD-9). Claude Code, Codex,
// Cursor, Copilot CLI and OpenCode reach every eligible account through
// vendor machine policy, and the enumerator writes targets.yaml rows for them
// only with enrollment.unenrolled_users: deny. The helper enrolls them for
// each account of the enumerator's eligible-accounts record instead, and only
// where targets.yaml is silent.

func TestEligibleAccountsParseKeepsOnlyUsableAccounts(t *testing.T) {
	accounts, err := ParseEligibleAccounts([]byte(`{"version": 1, "accounts": [
  {"user": "alice", "uid": 1001, "gid": 1001, "home": "/home/alice/", "home_inode": 42},
  {"user": "", "uid": 1002, "home": "/home/bob"},
  {"user": "root", "uid": 0, "home": "/root"},
  {"user": "erin", "uid": 1005, "home": "relative/home"},
  {"user": "frank", "uid": 1006, "home": "/"}
]}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []EligibleAccount{{User: "alice", UID: 1001, Home: "/home/alice"}}; !reflect.DeepEqual(accounts, want) {
		t.Fatalf("accounts = %+v, want %+v", accounts, want)
	}
	for _, bad := range []string{`{"version": 2, "accounts": []}`, `{"accounts": [`, `[]`} {
		if _, err := ParseEligibleAccounts([]byte(bad)); err == nil {
			t.Errorf("%s must be an error, so the caller keeps its previous enrollment", bad)
		}
	}
}

func TestLoadEligibleAccountsTrustAndMissing(t *testing.T) {
	dir := t.TempDir()
	path := EligibleAccountsPath(filepath.Join(dir, "targets.yaml"))
	if path != filepath.Join(dir, "eligible-accounts.json") {
		t.Fatalf("path = %s", path)
	}
	if accounts, err := LoadEligibleAccounts(path, nil); err != nil || accounts != nil {
		t.Fatalf("a missing record is no account: %+v %v", accounts, err)
	}
	if _, err := LoadEligibleAccounts("eligible-accounts.json", nil); err == nil {
		t.Fatal("a relative path must be refused, never read from the working directory")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"accounts":[{"user":"alice","uid":1001,"home":"/home/alice"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEligibleAccounts(path, func(string) error { return errors.New("not root-owned") }); err == nil {
		t.Fatal("an untrusted record must be refused")
	}
	accounts, err := LoadEligibleAccounts(path, func(string) error { return nil })
	if err != nil || len(accounts) != 1 || accounts[0].User != "alice" {
		t.Fatalf("%+v %v", accounts, err)
	}
}

func TestMachinePolicyRowsOnlyWhereTheManifestIsSilent(t *testing.T) {
	// alice has a manifest row for codex; the administrator disabled bob's
	// claudecode row; carol has no row at all.
	e := mustEnrollment(t, `targets:
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: codex
- user: bob
  uid: 1002
  user_home: /home/bob
  connector: claudecode
  enabled: false
`)
	accounts := []EligibleAccount{
		{User: "alice", UID: 1001, Home: "/home/alice"},
		{User: "bob", UID: 1002, Home: "/home/bob"},
		{User: "carol", UID: 1003, Home: "/home/carol"},
	}
	got := e.WithMachinePolicy(accounts, []string{"claudecode", "codex"})
	var rows []string
	for _, row := range got.Rows {
		rows = append(rows, fmt.Sprintf("%d:%s:%s:%t", row.UID, row.Home, row.Connector, row.MachinePolicy))
	}
	want := []string{
		"1001:/home/alice:claudecode:true", "1001:/home/alice:codex:false",
		"1002:/home/bob:codex:true", // the disabled claudecode row stays the administrator's choice
		"1003:/home/carol:claudecode:true", "1003:/home/carol:codex:true",
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v\nwant %v", rows, want)
	}
	for uid, connectors := range map[int][]string{1001: {"claudecode"}, 1002: {"codex"}, 1003: {"claudecode", "codex"}} {
		if got := got.MachinePolicyConnectors(uid); !reflect.DeepEqual(got, connectors) {
			t.Errorf("machine-policy connectors of %d = %v, want %v", uid, got, connectors)
		}
	}
	if !reflect.DeepEqual(got.Connectors(1001), []string{"claudecode", "codex"}) || got.UserOf(1003) != "carol" {
		t.Fatalf("enrollment helpers: %+v", got)
	}
	if len(e.Rows) != 1 || e.MachinePolicyConnectors(1001) != nil {
		t.Fatalf("WithMachinePolicy changed its receiver: %+v", e)
	}
	if again := got.WithMachinePolicy(accounts, []string{"claudecode", "codex"}); len(again.Rows) != len(got.Rows) {
		t.Fatalf("adding the same accounts twice duplicates rows: %+v", again.Rows)
	}
	if same := e.WithMachinePolicy(nil, []string{"claudecode"}); !reflect.DeepEqual(same.Rows, e.Rows) {
		t.Fatal("no account adds no row")
	}
	if same := e.WithMachinePolicy(accounts, nil); !reflect.DeepEqual(same.Rows, e.Rows) {
		t.Fatal("no machine-policy connector adds no row")
	}
}

// The golden case of the fix: on the default managed config an eligible
// account with a native Claude Code install and a live session is anchored
// by its pid in monitor mode, and the observe policy covers its home.
func TestAnEligibleAccountAloneAnchorsItsNativeClaude(t *testing.T) {
	w := newWorld(t, "")
	w.enroll = w.enroll.WithMachinePolicy([]EligibleAccount{{User: "alice", UID: 1001, Home: "/home/alice"}}, []string{"claudecode"})
	w.installs = ResolveInstalls(w.fs, w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	if len(w.installs) != 1 || !reflect.DeepEqual(w.installs[0].Native, []string{aliceClaudeOld, aliceClaudeNew}) {
		t.Fatalf("installs = %+v", w.installs)
	}
	roots := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew))
	if len(roots.Roots) != 1 {
		t.Fatalf("roots = %+v", roots.Roots)
	}
	c := w.compile(Input{Observe: true, Connect: true, Controls: &Scope{Mode: PolicyMonitor, UIDs: w.enroll.UIDs()}, Roots: roots.Roots})
	p := policyOf(t, c, FamilyControls)
	if fmt.Sprint(p.UIDs) != "[1001]" || fmt.Sprint(p.PIDs) != "[4001]" || len(p.Binaries) != 0 {
		t.Fatalf("uids %v pids %v binaries %v", p.UIDs, p.PIDs, p.Binaries)
	}
	if observe := policyOf(t, c, FamilyObserve); !strings.Contains(string(observe.YAML), "/home/alice/") {
		t.Fatalf("observe does not cover the eligible account's home:\n%s", observe.YAML)
	}
}

// The reconciler publishes such a user with the connectors it is enrolled
// for through machine policy, and counts it like any enrolled user.
func TestObserveReportsMachinePolicyUsers(t *testing.T) {
	h := newHarness(t, observeIntent(), "")
	h.w.enroll = h.w.enroll.WithMachinePolicy([]EligibleAccount{{User: "alice", UID: 1001, Home: "/home/alice"}}, []string{"claudecode"})
	h.w.installs = ResolveInstalls(h.w.fs, h.w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	h.procs = []Proc{nativeProc(4001, 1, 100, 1001, aliceClaudeNew)}
	h.pass()
	if _, ok := h.tg.find(FamilyControls); !ok {
		t.Fatalf("no controls policy for a machine-policy user: %v (warnings %v)", h.tg.names(), h.status().Warnings)
	}
	u := uidStatus(h.status(), 1001)
	if u.User != "alice" || !reflect.DeepEqual(u.Connectors, []string{"claudecode"}) || !reflect.DeepEqual(u.MachinePolicy, []string{"claudecode"}) ||
		u.State != UIDMonitor {
		t.Fatalf("alice = %+v", u)
	}
}
