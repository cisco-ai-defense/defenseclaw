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
	"testing"
)

// Guards of the Codex requirements heal that no test needed (review
// RV1928b, GAP-1989): each test fails when its guard line is removed.

// linkPublishedCodex puts a symbolic link to a file of its own in place of
// the published Codex requirements file and returns the link's target.
func linkPublishedCodex(t *testing.T, path string) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "linked.toml")
	writeFile(t, target, "[features]\nhooks = false\n")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	return target
}

// A link pointed somewhere else between the read and the rename is another
// writer's change: the publish is refused and the new link stays.
func TestGAP1989PublishRefusesALinkRetargetedBeforeTheRename(t *testing.T) {
	opts, path, _ := publishedCodex(t)
	linkPublishedCodex(t, path)
	retargeted := filepath.Join(t.TempDir(), "retargeted.toml")
	writeFile(t, retargeted, "[features]\nhooks = false\n")
	previous := policyFileSwapHook
	t.Cleanup(func() { policyFileSwapHook = previous })
	policyFileSwapHook = func(at string) {
		if filepath.Clean(at) != filepath.Clean(path) {
			return
		}
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(retargeted, path); err != nil {
			t.Error(err)
		}
	}
	if _, err := (codexTarget{}).Reconcile(opts); !errors.Is(err, errPolicyFileChanged) {
		t.Fatalf("publish over a link retargeted after the read: %v, want the changed-file refusal", err)
	}
	if target, err := os.Readlink(path); err != nil || target != retargeted {
		t.Fatalf("the retargeted link was replaced: %q %v", target, err)
	}
}

// Reconcile (which adopts administrator edits) over a link at the published
// path keeps the recorded administrator text: what the link points at is not
// an edit to adopt.
func TestGAP1989ReconcileOverALinkKeepsTheRecordedAdministratorText(t *testing.T) {
	opts, path, published := publishedCodex(t)
	target := linkPublishedCodex(t, path)
	adopt := opts
	adopt.AdoptAdministratorEdits = true
	state := mustReconcile(t, codexTarget{}, adopt)
	if got := readFile(t, path); got != published {
		t.Fatalf("reconcile over a link did not put back the published file with the administrator's text:\n%s", got)
	}
	if state.ReplacedLink != target {
		t.Fatalf("ReplacedLink = %q, want %q", state.ReplacedLink, target)
	}
}

// A publish another writer's save refused replaced nothing, so it keeps no
// copy and says nothing about one (GAP-1990).
func TestGAP1990RefusedPublishKeepsNoCopy(t *testing.T) {
	opts, path, published := publishedCodex(t)
	dir := filepath.Join(filepath.Dir(path), replacedPolicyDirName)
	writeFile(t, path, adminNote(published))
	previous := policyFileSwapHook
	saveDuringSwap(t, path, -1, func(current string) string { return current + "# saved again\n" })
	state, err := (codexTarget{}).Reconcile(opts)
	if !errors.Is(err, errPolicyFileChanged) {
		t.Fatalf("publish under a racing save: %v, want the changed-file refusal", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 || state.SavedEdit != "" {
		t.Fatalf("a refused publish kept %d copies (SavedEdit %q)", len(entries), state.SavedEdit)
	}
	policyFileSwapHook = previous
	latest := readFile(t, path)
	state = mustReconcile(t, codexTarget{}, opts)
	if entries, _ := os.ReadDir(dir); len(entries) != 1 || state.SavedEdit == "" || readFile(t, state.SavedEdit) != latest {
		t.Fatalf("the publish after the race kept %d copies (SavedEdit %q), want one of the newest file", len(entries), state.SavedEdit)
	}
}
