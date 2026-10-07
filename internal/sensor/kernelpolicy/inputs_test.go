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
	"time"
)

func TestIntentFromLookupFallsBackToTheNarrowSide(t *testing.T) {
	env := func(pairs ...string) Lookup {
		m := map[string]string{}
		for i := 0; i < len(pairs); i += 2 {
			m[pairs[i]] = pairs[i+1]
		}
		return func(name string) (string, bool) { v, ok := m[name]; return v, ok }
	}
	cases := []struct {
		name string
		env  Lookup
		want Intent
	}{
		{"absent", env(), Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn}},
		{"nil lookup", nil, Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn}},
		{"empty mode is consume", env(EnvMode, ""), Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn}},
		{"all four", env(EnvMode, "enforce", EnvBurnIn, "72h", EnvEnforceAck, "sha256:3f9c2a7d41b0", EnvEnforceConnectors, "codex, claudecode,codex"),
			Intent{Mode: ModeEnforce, BurnIn: 72 * time.Hour, EnforceAck: "sha256:3f9c2a7d41b0", EnforceConnectors: []string{"claudecode", "codex"}}},
		{"burn-in 0 is allowed", env(EnvBurnIn, "0"), Intent{Mode: ModeConsume, BurnIn: 0}},
		{"bad mode is consume", env(EnvMode, "enforced"),
			Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn, Problems: []string{WarnConfigInvalid + ":" + EnvMode}}},
		{"burn-in below the minimum is the default", env(EnvBurnIn, "1h"),
			Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn, Problems: []string{WarnConfigInvalid + ":" + EnvBurnIn}}},
		{"burn-in above the maximum is the default", env(EnvBurnIn, "9000h"),
			Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn, Problems: []string{WarnConfigInvalid + ":" + EnvBurnIn}}},
		{"negative burn-in is the default", env(EnvBurnIn, "-24h"),
			Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn, Problems: []string{WarnConfigInvalid + ":" + EnvBurnIn}}},
		{"a malformed ack is no ack", env(EnvMode, "enforce", EnvEnforceAck, "sha256:XYZ"),
			Intent{Mode: ModeEnforce, BurnIn: DefaultBurnIn, Problems: []string{WarnConfigInvalid + ":" + EnvEnforceAck}}},
		{"a malformed connector is dropped", env(EnvMode, " OFF ", EnvEnforceConnectors, "Codex,bad connector,,codex"),
			Intent{Mode: ModeOff, BurnIn: DefaultBurnIn, EnforceConnectors: []string{"codex"},
				Problems: []string{WarnConfigInvalid + ":" + EnvEnforceConnectors}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IntentFromLookup(tc.env); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
	for _, m := range []string{"off", "consume", "observe", "enforce"} {
		if mode, err := ParseMode(m); err != nil || string(mode) != m {
			t.Errorf("ParseMode(%q) = %v %v", m, mode, err)
		}
	}
	if (Intent{Mode: ModeEnforce, EnforceAck: "a"}).Key() == (Intent{Mode: ModeEnforce, EnforceAck: "b"}).Key() ||
		(Intent{Mode: ModeEnforce}).Key() == (Intent{Mode: ModeObserve}).Key() {
		t.Fatal("the intent key must change with the mode and the approval")
	}
}

func TestFamilyNames(t *testing.T) {
	for name, want := range map[string]Family{
		"defenseclaw-observe-0123abcd":         FamilyObserve,
		"defenseclaw-connect-0123abcd":         FamilyConnect,
		"defenseclaw-controls-0123abcd":        FamilyControls,
		"defenseclaw-controls-burnin-0123abcd": FamilyBurnin,
	} {
		if got, ok := FamilyOfName(name); !ok || got != want {
			t.Errorf("FamilyOfName(%q) = %v %v", name, got, ok)
		}
	}
	for _, bad := range []string{"", "defenseclaw-observe-0123ABCD", "defenseclaw-observe-0123abc", "defenseclaw-observe-0123abcde",
		"defenseclaw-other-0123abcd", "xdefenseclaw-observe-0123abcd", "defenseclaw-observe-0123abcd\n", "../defenseclaw-observe-0123abcd"} {
		if IsDefenseClawName(bad) {
			t.Errorf("%q should not be a DefenseClaw name", bad)
		}
	}
}

func TestEnrollmentParse(t *testing.T) {
	lookup := func(name string) (int, string, error) {
		if name == "carol" {
			return 1003, "/home/carol", nil
		}
		return 0, "", errors.New("no such user")
	}
	e, err := ParseEnrollment([]byte(`targets:
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: ClaudeCode
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: claudecode
- user: carol
  connector: codex
- user: dave
  uid: 1004
  user_home: /home/dave
  connector: codex
  enabled: false
- user: root
  uid: 0
  user_home: /root
  connector: codex
- user: erin
  uid: 1005
  user_home: relative/home
- user: frank
  uid: 1006
  user_home: /
- user: nobody-known
  connector: amp
`), lookup)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range e.Rows {
		got = append(got, fmt.Sprintf("%d:%s:%s", r.UID, r.Home, r.Connector))
	}
	want := []string{"1001:/home/alice:claudecode", "1003:/home/carol:codex"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %v, want %v (duplicates, disabled rows, root, unusable homes and unknown users are dropped)", got, want)
	}
	if e.ConnectorsDigest(1001) == e.ConnectorsDigest(1003) || e.UserOf(1001) != "alice" || !e.Has(1003) || e.Has(0) {
		t.Fatalf("enrollment helpers: %+v", e)
	}
	if empty, err := ParseEnrollment(nil, nil); err != nil || len(empty.Rows) != 0 {
		t.Fatalf("empty manifest: %+v %v", empty, err)
	}
	if _, err := ParseEnrollment([]byte("targets: [unclosed"), nil); err == nil {
		t.Fatal("a broken manifest must be an error, so the caller keeps its previous enrollment")
	}
}

func TestLoadEnrollmentTrustAndMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yaml")
	if e, err := LoadEnrollment(path, nil, nil); err != nil || len(e.Rows) != 0 {
		t.Fatalf("a missing manifest is an empty enrollment: %+v %v", e, err)
	}
	if err := os.WriteFile(path, []byte(baseTargets), 0o600); err != nil {
		t.Fatal(err)
	}
	refuse := func(string) error { return errors.New("not root-owned") }
	if _, err := LoadEnrollment(path, refuse, nil); err == nil {
		t.Fatal("an untrusted manifest must be refused")
	}
	e, err := LoadEnrollment(path, func(string) error { return nil }, nil)
	if err != nil || len(e.Rows) != 3 {
		t.Fatalf("%+v %v", e, err)
	}
	if !reflect.DeepEqual(e.UIDs(), []int{1001, 1002}) || !reflect.DeepEqual(e.Connectors(1001), []string{"claudecode", "codex"}) {
		t.Fatalf("%+v", e)
	}
}

func TestInstallsAreResolvedAndClassified(t *testing.T) {
	w := newWorld(t, baseTargets)
	byKey := map[string]Install{}
	for _, in := range w.installs {
		byKey[fmt.Sprintf("%d/%s", in.UID, in.Connector)] = in
	}
	claude := byKey["1001/claudecode"]
	if !reflect.DeepEqual(claude.Native, []string{aliceClaudeOld, aliceClaudeNew}) || len(claude.Entries) != 0 {
		t.Fatalf("claude = %+v", claude)
	}
	codex := byKey["1001/codex"]
	if len(codex.Native) != 0 || !reflect.DeepEqual(codex.Entries, []string{codexEntry}) {
		t.Fatalf("a script-hosted install must be an entry, never a native anchor: %+v", codex)
	}
	if !byKey["1002/codex"].Resolved() {
		t.Fatal("bob's codex comes from the shared prefix")
	}
}

func TestInstallsRefuseUntrustedPathsAndStrangers(t *testing.T) {
	w := newWorld(t, baseTargets)
	w.fs.untrusted = []string{"/opt/agents"} // another account can change it
	installs := ResolveInstalls(w.fs, w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	for _, in := range installs {
		if in.Connector == "codex" && in.Resolved() {
			t.Fatalf("%+v: an install another account can change must never anchor", in)
		}
	}
	// A prefix that is not absolute, or is "/", is ignored.
	for _, prefix := range []string{"relative", "/", ""} {
		got := searchDirs(w.fs, "/home/alice", ResolveOptions{ExtraPrefixes: []string{prefix}})
		for _, dir := range got {
			if dir == "bin" || dir == "/bin" && prefix == "/" {
				t.Errorf("prefix %q produced %q", prefix, dir)
			}
		}
	}
	// A non-CLI connector (an IDE) has no install to anchor.
	e := mustEnrollment(t, `targets:
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: antigravity
- user: alice
  uid: 1001
  user_home: /home/alice
`)
	if got := ResolveInstalls(w.fs, e, ResolveOptions{}); len(got) != 0 {
		t.Fatalf("installs = %+v", got)
	}
	// A link in the home that leaves the home is never used, however trusted
	// its target: the user controls it.
	w2 := newWorld(t, baseTargets)
	w2.fs.elf("/srv/shared/claude")
	w2.fs.symlink("/home/alice/bin/claude", "/srv/shared/claude")
	for _, in := range ResolveInstalls(w2.fs, w2.enroll, ResolveOptions{}) {
		if in.UID == 1001 && in.Connector == "claudecode" && containsStr(in.Native, "/srv/shared/claude") {
			t.Fatalf("link out of the home to an untrusted target was accepted: %+v", in)
		}
	}
}

func TestOnlyInterpretersIdentifyScriptHostedRoots(t *testing.T) {
	w := newWorld(t, baseTargets)
	editor := Proc{PID: 9001, PPID: 1, StartTicks: 1, UID: 1001, EUID: 1001, Host: true, Exe: "/usr/bin/vim",
		Cmdline: []string{"vim", "/opt/agents/bin/codex"}, Comm: "vim"}
	if roots := w.roots(editor); len(roots.Roots) != 0 {
		t.Fatalf("an editor that merely names the entry file is not an agent: %+v", roots.Roots)
	}
	relative := codexProc(9002, 1, 2, 1001)
	relative.Cmdline = []string{"node", "../bin/codex"}
	relative.Cwd = "/opt/agents/lib"
	if roots := w.roots(relative); len(roots.Roots) != 1 {
		t.Fatalf("a relative script path resolves against the process's cwd: %+v", roots.Roots)
	}
	noCwd := codexProc(9003, 1, 3, 1001)
	noCwd.Cmdline = []string{"node", "../bin/codex"}
	if roots := w.roots(noCwd); len(roots.Roots) != 0 {
		t.Fatalf("a relative path without a cwd cannot be resolved: %+v", roots.Roots)
	}
	setuid := codexProc(9004, 1, 4, 1001)
	setuid.EUID = 0
	if roots := w.roots(setuid); len(roots.Roots) != 0 {
		t.Fatalf("a process whose effective uid differs is not the enrolled user's: %+v", roots.Roots)
	}
	other := codexProc(9005, 1, 5, 1002)
	other.Cmdline = []string{"node", aliceClaudeNew} // bob running alice's file
	if roots := w.roots(other); len(roots.Roots) != 0 {
		t.Fatalf("%+v", roots.Roots)
	}
}

func TestPidReuseIsNotTheSameRoot(t *testing.T) {
	w := newWorld(t, baseTargets)
	first := nativeProc(4001, 1, 100, 1001, aliceClaudeNew)
	if len(w.roots(first).Roots) != 1 {
		t.Fatal("no root")
	}
	// The pid is reused by an unrelated process.
	reused := Proc{PID: 4001, PPID: 1, StartTicks: 999, UID: 1001, EUID: 1001, Host: true, Exe: "/usr/bin/sleep",
		Cmdline: []string{"sleep", "9"}, Comm: "sleep"}
	if roots := w.roots(reused); len(roots.Roots) != 0 {
		t.Fatalf("a reused pid stayed a root: %+v", roots.Roots)
	}
}

func TestCLIConnectorsCoverOnlyCLIs(t *testing.T) {
	for _, connector := range []string{"antigravity", "windsurf", "cursor-ide", "kiro-ide", "", "vscode"} {
		if IsCLIConnector(connector) {
			t.Errorf("%q is not an anchorable CLI", connector)
		}
	}
	for connector, probe := range cliConnectors {
		if len(probe.binaries) == 0 {
			t.Errorf("%s has no binary", connector)
		}
		if strings.ToLower(connector) != connector {
			t.Errorf("%s is not normalized", connector)
		}
	}
}
