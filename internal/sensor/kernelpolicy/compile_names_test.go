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
	"slices"
	"testing"

	kernel "github.com/defenseclaw/defenseclaw/policies/kernel"
)

// namesFS adds hard link counts and dentry names to the in-memory tree.
type namesFS struct {
	FS
	links  map[string]uint64
	dentry map[string]string
}

func (n namesFS) Links(p string) (uint64, bool) {
	v, ok := n.links[p]
	return v, ok
}

func (n namesFS) DentryPath(p string) (string, bool) {
	if v, ok := n.dentry[p]; ok {
		return v, true
	}
	return p, true
}

func compileNames(t *testing.T, fsys FS) Compiled {
	t.Helper()
	w := newWorld(t, baseTargets)
	out, err := Compile(Input{Enrollment: w.enroll, Installs: w.installs, FS: fsys,
		Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{1001}}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func hookValues(p Policy, hook string) []string {
	var out []string
	for _, h := range p.tp.Spec.LsmHooks {
		if h.Hook != hook {
			continue
		}
		for _, sel := range h.Selectors {
			if len(sel.MatchArgs) > 0 {
				out = append(out, sel.MatchArgs[0].Values...)
			}
		}
	}
	return out
}

// The authorized keys files are refused for write opens, new hard links
// and renames; the .ssh directory only for renames. The path index names
// the new control for each.
func TestAuthorizedKeysSelectors(t *testing.T) {
	c := compileNames(t, newWorld(t, baseTargets).fs)
	p := policyOf(t, c, FamilyControls)
	keys := "/home/alice/.ssh/authorized_keys"
	if !slices.Contains(hookValues(p, "file_open"), keys) {
		t.Fatalf("file_open does not name %s: %v", keys, hookValues(p, "file_open"))
	}
	if link := hookValues(p, "path_link"); !slices.Contains(link, keys) || slices.Contains(link, "/home/alice/.ssh") {
		t.Fatalf("path_link values = %v", link)
	}
	if rename := hookValues(p, "path_rename"); !slices.Contains(rename, keys) || !slices.Contains(rename, "/home/alice/.ssh") {
		t.Fatalf("path_rename values = %v", rename)
	}
	for _, path := range []string{keys, "/home/alice/.ssh/authorized_keys2", "/home/alice/.ssh"} {
		if got := p.Paths.ControlOf(path); got != kernel.ControlSSHAuthorizedKeysWrite {
			t.Errorf("ControlOf(%s) = %q", path, got)
		}
	}
	if got := p.Paths.ControlOf("/home/alice/.bashrc"); got != kernel.ControlPersistenceWrite {
		t.Errorf("ControlOf(.bashrc) = %q", got)
	}
	// Bob is not in scope: none of his paths may appear.
	for _, hook := range []string{"file_open", "path_link", "path_rename"} {
		for _, v := range hookValues(p, hook) {
			if inside("/home/bob", v) {
				t.Fatalf("%s names another user's path %s", hook, v)
			}
		}
	}
}

// A protected file with a second hard link is reported by path only.
func TestExtraHardLinkIsReported(t *testing.T) {
	keys := "/home/alice/.ssh/authorized_keys"
	c := compileNames(t, namesFS{FS: newWorld(t, baseTargets).fs, links: map[string]uint64{keys: 2, "/home/alice/.bashrc": 1}})
	if !slices.Contains(c.Notes, NoteExtraLinks+":"+keys) {
		t.Fatalf("notes = %v, want %s:%s", c.Notes, NoteExtraLinks, keys)
	}
	for _, note := range c.Notes {
		if note == NoteExtraLinks+":/home/alice/.bashrc" {
			t.Fatal("a file with one link was reported")
		}
	}
}

// A home whose dentries Tetragon names differently (not on the root mount)
// keeps its file_open selector and loses only the link and rename paths,
// with a note: a rewritten name would never match.
func TestDentryOffRootMountIsLeftOut(t *testing.T) {
	keys := "/home/alice/.ssh/authorized_keys"
	fsys := namesFS{FS: newWorld(t, baseTargets).fs, dentry: map[string]string{
		keys: "/alice/.ssh/authorized_keys", "/home/alice/.ssh/authorized_keys2": "/alice/.ssh/authorized_keys2",
		"/home/alice/.ssh": "/alice/.ssh",
	}}
	c := compileNames(t, fsys)
	p := policyOf(t, c, FamilyControls)
	if !slices.Contains(hookValues(p, "file_open"), keys) {
		t.Fatal("file_open lost the authorized keys file")
	}
	if hookCount(p, "path_link")+hookCount(p, "path_rename") != 0 {
		t.Fatalf("link/rename hooks kept with unmatched names: %s", p.YAML)
	}
	if !slices.Contains(c.Notes, NoteDentryMount+":"+keys) {
		t.Fatalf("notes = %v", c.Notes)
	}
}
