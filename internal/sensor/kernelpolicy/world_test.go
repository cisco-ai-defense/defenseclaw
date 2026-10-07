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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Decoy users and paths only: nothing here names a real account, and no
// test ever opens a real credential file.
const (
	aliceClaudeOld = "/home/alice/.local/share/claude/versions/2.1.100"
	aliceClaudeNew = "/home/alice/.local/share/claude/versions/2.1.101"
	codexEntry     = "/opt/agents/lib/node_modules/@openai/codex/bin/codex.js"
)

const baseTargets = `targets:
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: claudecode
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: codex
- user: bob
  uid: 1002
  user_home: /home/bob
  connector: codex
`

func baseFS() *memFS {
	m := newMemFS()
	m.mkdir("/home/alice", "/home/bob", "/home/carol", "/etc")
	for _, p := range []string{"/usr/bin/ssh", "/usr/bin/ssh-keygen", "/usr/bin/ssh-add", "/usr/bin/node"} {
		m.elf(p)
	}
	m.elf(aliceClaudeOld)
	m.elf(aliceClaudeNew)
	m.symlink("/home/alice/.local/bin/claude", aliceClaudeNew)
	m.script(codexEntry)
	m.symlink("/opt/agents/bin/codex", "../lib/node_modules/@openai/codex/bin/codex.js")
	return m
}

func mustEnrollment(t *testing.T, yaml string) Enrollment {
	t.Helper()
	e, err := ParseEnrollment([]byte(yaml), nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// nativeProc is a native Claude Code session of uid.
func nativeProc(pid, ppid int, ticks uint64, uid int, exe string) Proc {
	return Proc{PID: pid, PPID: ppid, StartTicks: ticks, UID: uid, EUID: uid, Exe: exe, Host: true,
		Cmdline: []string{exe}, Comm: "claude"}
}

// codexProc is an npm Codex session: node running the wrapper script.
func codexProc(pid, ppid int, ticks uint64, uid int) Proc {
	return Proc{PID: pid, PPID: ppid, StartTicks: ticks, UID: uid, EUID: uid, Exe: "/usr/bin/node", Host: true,
		Cmdline: []string{"node", "/opt/agents/bin/codex"}, Comm: "node"}
}

type world struct {
	t        *testing.T
	fs       *memFS
	enroll   Enrollment
	installs []Install
	tracker  *Tracker
}

func newWorld(t *testing.T, targets string) *world {
	t.Helper()
	w := &world{t: t, fs: baseFS(), tracker: NewTracker()}
	w.enroll = mustEnrollment(t, targets)
	w.installs = ResolveInstalls(w.fs, w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	return w
}

func (w *world) roots(procs ...Proc) RootSet {
	return w.tracker.Update(w.fs, procs, w.installs, w.enroll)
}

func (w *world) compile(in Input) Compiled {
	w.t.Helper()
	in.Enrollment, in.Installs, in.FS = w.enroll, w.installs, w.fs
	out, err := Compile(in)
	if err != nil {
		w.t.Fatal(err)
	}
	return out
}

func policyOf(t *testing.T, c Compiled, family Family) Policy {
	t.Helper()
	for _, p := range c.Policies {
		if p.Family == family {
			return p
		}
	}
	t.Fatalf("no %s policy in %v (notes %v)", family, familiesOf(c), c.Notes)
	return Policy{}
}

func hasFamily(c Compiled, family Family) bool {
	for _, p := range c.Policies {
		if p.Family == family {
			return true
		}
	}
	return false
}

func familiesOf(c Compiled) []Family {
	var out []Family
	for _, p := range c.Policies {
		out = append(out, p.Family)
	}
	return out
}

// golden compares got with testdata/<name>.golden.yaml. The file is rewritten
// only when DEFENSECLAW_UPDATE_GOLDEN=1.
func golden(t *testing.T, name string, c Compiled) {
	t.Helper()
	var buf bytes.Buffer
	for i, p := range c.Policies {
		if i > 0 {
			buf.WriteString("---\n")
		}
		buf.Write(p.YAML)
	}
	for _, note := range c.Notes {
		buf.WriteString("# note: " + note + "\n")
	}
	file := filepath.Join("testdata", name+".golden.yaml")
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(file, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("missing golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Fatalf("%s drifted (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1):\n--- want\n%s\n--- got\n%s", file, want, buf.Bytes())
	}
}

// selectorsOf returns the selectors of every hook of a controls policy.
func selectorsOf(t *testing.T, p Policy) [][]tpSelector {
	t.Helper()
	var out [][]tpSelector
	for _, hook := range p.tp.Spec.LsmHooks {
		out = append(out, hook.Selectors)
	}
	return out
}

func hasBinary(p Policy, want string) bool {
	for _, b := range p.Binaries {
		if b == want {
			return true
		}
	}
	return false
}

func containsStr(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func anyContains(list []string, fragment string) bool {
	for _, item := range list {
		if strings.Contains(item, fragment) {
			return true
		}
	}
	return false
}
