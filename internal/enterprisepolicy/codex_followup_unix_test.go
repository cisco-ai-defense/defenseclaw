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

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Follow-ups of GAP-1928 (review RV1928): the guardian check of a merged
// document that no longer parses (GAP-1966), a copy of the edit a publish
// replaces (GAP-1967), a symbolic link put in place of the file (GAP-1968)
// and the pin of the bytes the publish checked.

func publishedCodex(t *testing.T) (Options, string, string) {
	t.Helper()
	opts := testOptions(t)
	path := codexPath(t, opts)
	writeFile(t, path, adminCodexRequirements)
	mustReconcile(t, codexTarget{}, opts)
	return opts, path, readFile(t, path)
}

func TestGAP1966TamperedCodexRequirementsListsADocumentThatNoLongerParses(t *testing.T) {
	opts, path, published := publishedCodex(t)
	event := regexp.MustCompile(`\[\[hooks\.([A-Za-z]+)\]\]`).FindStringSubmatch(published)
	if event == nil {
		t.Fatalf("no hook event in:\n%s", published)
	}
	for name, data := range map[string]string{
		// A table of the name of DefenseClaw's hook array, between the
		// blocks: the stripped file re-renders to itself, but the whole
		// document does not parse.
		"table collision between": strings.Replace(adminNote(published), "# administrator note\n", "[hooks."+event[1]+"]\n", 1),
		// The administrator text gains a byte order mark it did not have.
		"byte order mark added": "\ufeff" + published,
	} {
		t.Run(name, func(t *testing.T) {
			writeFile(t, path, data)
			if got, tampered := TamperedCodexRequirements(opts); !tampered || got != path {
				t.Fatalf("TamperedCodexRequirements = %q, %v; want %q, true", got, tampered, path)
			}
			mustReconcile(t, codexTarget{}, opts)
			if got := readFile(t, path); got != published {
				t.Fatalf("publish did not put back the published file:\n%s", got)
			}
			if _, tampered := TamperedCodexRequirements(opts); tampered {
				t.Fatal("still listed after the publish")
			}
		})
	}
}

func TestGAP1967PublishKeepsARootOnlyCopyOfTheEditItReplaces(t *testing.T) {
	opts, path, published := publishedCodex(t)
	dir := filepath.Join(filepath.Dir(path), replacedPolicyDirName)
	edited := adminNote(published)
	writeFile(t, path, edited)
	state := mustReconcile(t, codexTarget{}, opts)
	if got := readFile(t, path); got != published {
		t.Fatalf("publish did not put back the published file:\n%s", got)
	}
	if filepath.Dir(state.SavedEdit) != dir || !strings.HasPrefix(filepath.Base(state.SavedEdit), "requirements.toml.20260926T120000Z") {
		t.Fatalf("SavedEdit = %q, want a copy in %s", state.SavedEdit, dir)
	}
	if got := readFile(t, state.SavedEdit); got != edited {
		t.Fatalf("the copy is not the replaced file:\n%s", got)
	}
	if !strings.Contains(strings.Join(state.Details, "\n"), state.SavedEdit) {
		t.Fatalf("the details do not name the copy: %v", state.Details)
	}
	for name, want := range map[string]os.FileMode{dir: 0o700, state.SavedEdit: 0o600} {
		info, err := os.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s has mode %v, want %v", name, info.Mode().Perm(), want)
		}
	}
	// A publish over the file it wrote, and a publish that adopts an edit,
	// keep nothing.
	if state := mustReconcile(t, codexTarget{}, opts); state.SavedEdit != "" {
		t.Fatalf("a publish over the published file kept %q", state.SavedEdit)
	}
	adopt := opts
	adopt.AdoptAdministratorEdits = true
	writeFile(t, path, edited)
	if state := mustReconcile(t, codexTarget{}, adopt); state.SavedEdit != "" || readFile(t, path) != edited {
		t.Fatalf("adopting kept %q or dropped the edit:\n%s", state.SavedEdit, readFile(t, path))
	}
	// Only the newest copies stay.
	accepted := readFile(t, path)
	for i := 0; i < replacedPolicyKept+3; i++ {
		writeFile(t, path, accepted+"# tamper "+string(rune('a'+i))+"\n")
		if state := mustReconcile(t, codexTarget{}, opts); state.SavedEdit == "" {
			t.Fatalf("publish %d kept no copy", i)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != replacedPolicyKept {
		t.Fatalf("%d copies kept, want %d", len(entries), replacedPolicyKept)
	}
	if newest := readFile(t, filepath.Join(dir, entries[len(entries)-1].Name())); !strings.Contains(newest, "# tamper "+string(rune('a'+replacedPolicyKept+2))) {
		t.Fatalf("the newest copy was pruned:\n%s", newest)
	}
}

func TestGAP1968PublishReplacesASymbolicLinkWithoutFollowingIt(t *testing.T) {
	opts, path, published := publishedCodex(t)
	other := filepath.Join(t.TempDir(), "other.toml")
	const linked = "[features]\nhooks = false\n"
	writeFile(t, other, linked)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if !CodexRequirementsDrifted(opts) {
		t.Fatal("a symbolic link does not read as drifted")
	}
	if _, tampered := TamperedCodexRequirements(opts); !tampered {
		t.Fatal("the guardian check does not list a symbolic link")
	}
	state := mustReconcile(t, codexTarget{}, opts)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the link was not replaced by a regular file: %v %v", info, err)
	}
	if got := readFile(t, path); got != published {
		t.Fatalf("publish did not put back the published file:\n%s", got)
	}
	if got := readFile(t, other); got != linked {
		t.Fatalf("publish wrote through the link:\n%s", got)
	}
	if !state.Changed || state.ReplacedLink != other || state.SavedEdit != "" {
		t.Fatalf("state: changed %v, replaced link %q, saved %q", state.Changed, state.ReplacedLink, state.SavedEdit)
	}
	if CodexRequirementsDrifted(opts) {
		t.Fatal("still drifted after the publish")
	}
	// A link at a path DefenseClaw never published is left as it is.
	fresh := testOptions(t)
	freshPath := codexPath(t, fresh)
	if err := os.MkdirAll(filepath.Dir(freshPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, freshPath); err != nil {
		t.Fatal(err)
	}
	if _, err := (codexTarget{}).Reconcile(fresh); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a first publish over an administrator's link: %v", err)
	}
	if target, err := os.Readlink(freshPath); err != nil || target != other {
		t.Fatalf("the administrator's link was changed: %q %v", target, err)
	}
}

func TestGAP1928PublishedCodexPolicyViewDigestHashesOnlyTheCheckedBytes(t *testing.T) {
	opts, path, published := publishedCodex(t)
	want, err := PolicyViewDigest(opts, codexConnector)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := PublishedCodexPolicyViewDigest(opts); err != nil || got != want {
		t.Fatalf("PublishedCodexPolicyViewDigest = %q, %v; want %q", got, err, want)
	}
	writeFile(t, path, published+"# raced\n")
	if got, err := PublishedCodexPolicyViewDigest(opts); !errors.Is(err, ErrCodexRequirementsChanged) {
		t.Fatalf("a changed file was hashed: %q, %v", got, err)
	}
}
