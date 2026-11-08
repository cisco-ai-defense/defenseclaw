//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0758: a teardown, a read and the publication of an empty enrollment keep
// a link at a recorded vendor folder and name it; they neither follow it nor
// create the folder. Install, ensure and repair still refuse it.

// linkProbe makes every path equal to or below one of links a reparse point,
// whatever is on the disk, the way the real chain walk reports one.
func linkProbe(links ...string) func(string) (string, error) {
	return func(path string) (string, error) {
		path = strings.ToLower(filepath.Clean(path))
		for _, link := range links {
			l := strings.ToLower(filepath.Clean(link))
			if path == l || strings.HasPrefix(path, l+`\`) {
				return link, nil
			}
		}
		return "", nil
	}
}

type keptFixture struct {
	cursor, claudeDir, selectorDir, perUserDir string
	recorded                                   *[][]string
}

// useKeptFixture points the Cursor folder, the Claude managed-settings.d
// folder, a machine-policy selector folder and a per-user enrollment folder
// at scratch paths. link names the paths that are reparse points.
func useKeptFixture(t *testing.T, standalone bool, link func(f keptFixture) []string) keptFixture {
	t.Helper()
	base := t.TempDir()
	f := keptFixture{
		cursor:      filepath.Join(base, "ProgramData", "Cursor"),
		claudeDir:   filepath.Join(base, "Program Files", "ClaudeCode", "managed-settings.d"),
		selectorDir: filepath.Join(base, "ProgramData", "OpenAI", "Codex"),
		perUserDir:  filepath.Join(base, "runtime", "copilot"),
	}
	var recorded [][]string
	f.recorded = &recorded
	previousStandalone, previousIdentity, previousProbe := windowsEnterpriseStandaloneProcess, windowsEnterpriseMutationIdentityCheck, windowsReparseChainProbe
	previousCursor, previousClaude, previousSelector := windowsCursorManagedRootResolver, windowsClaudeManagedPolicyPathResolver, windowsManagedRuntimeSelectorPathResolver
	previousPerUser, previousRecorder, previousAuthorize := windowsPerUserManagedRuntimeDirResolver, windowsCreatedFolderRecorder, windowsManagedRuntimeSelectorMutationAuthorize
	previousDir, previousAncestor := windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess, windowsEnterpriseMutationIdentityCheck, windowsReparseChainProbe = previousStandalone, previousIdentity, previousProbe
		windowsCursorManagedRootResolver, windowsClaudeManagedPolicyPathResolver, windowsManagedRuntimeSelectorPathResolver = previousCursor, previousClaude, previousSelector
		windowsPerUserManagedRuntimeDirResolver, windowsCreatedFolderRecorder, windowsManagedRuntimeSelectorMutationAuthorize = previousPerUser, previousRecorder, previousAuthorize
		windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck = previousDir, previousAncestor
		windowsManagedPolicyKept.Lock()
		windowsManagedPolicyKept.paths = map[string]string{}
		windowsManagedPolicyKept.Unlock()
	})
	windowsManagedPolicyKept.Lock()
	windowsManagedPolicyKept.paths = map[string]string{}
	windowsManagedPolicyKept.Unlock()
	windowsEnterpriseStandaloneProcess = func() bool { return standalone }
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	windowsManagedPolicyDirTrustCheck = trustAll
	windowsManagedPolicyAncestorTrustCheck = trustAll
	windowsCursorManagedRootResolver = func() (string, error) { return f.cursor, nil }
	windowsClaudeManagedPolicyPathResolver = func() (string, error) {
		return filepath.Join(f.claudeDir, windowsClaudeManagedPolicyFile), nil
	}
	windowsManagedRuntimeSelectorPathResolver = func(string) (string, error) {
		return filepath.Join(f.selectorDir, windowsManagedRuntimeSelectorFile), nil
	}
	windowsPerUserManagedRuntimeDirResolver = func(string) (string, error) { return f.perUserDir, nil }
	windowsCreatedFolderRecorder = func(created []string) error {
		recorded = append(recorded, append([]string(nil), created...))
		return nil
	}
	if link != nil {
		windowsReparseChainProbe = linkProbe(link(f)...)
	}
	return f
}

// plant writes a file where a link target would hold one, so a test can tell
// that nothing behind the link was read or changed.
func plant(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("%s should exist: %v", path, err)
	}
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s should not exist (Lstat error %v)", path, err)
	}
}

func TestInspectManagedPolicyDirectoryNoFollowClassifiesWithoutTouching(t *testing.T) {
	root := t.TempDir()
	absent := filepath.Join(root, "absent")
	plain := filepath.Join(root, "plain")
	file := filepath.Join(root, "file")
	linked := filepath.Join(root, "linked")
	for _, dir := range []string{plain, linked} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	plant(t, file, "x")
	previous := windowsReparseChainProbe
	t.Cleanup(func() { windowsReparseChainProbe = previous })
	windowsReparseChainProbe = linkProbe(linked)
	for _, tc := range []struct {
		name string
		path string
		want windowsManagedPolicyDirState
		kept string
	}{
		{"absent", absent, windowsManagedPolicyDirAbsent, ""},
		{"plain", plain, windowsManagedPolicyDirPlain, ""},
		{"a link", linked, windowsManagedPolicyDirKept, linked},
		{"below a link", filepath.Join(linked, "Codex"), windowsManagedPolicyDirKept, linked},
		{"a file", file, windowsManagedPolicyDirKept, file},
	} {
		state, kept, err := inspectWindowsManagedPolicyDirectoryNoFollow(tc.path)
		if err != nil || state != tc.want || kept != tc.kept {
			t.Errorf("%s: state %d kept %q err %v, want state %d kept %q", tc.name, state, kept, err, tc.want, tc.kept)
		}
	}
	mustNotExist(t, absent)
	mustExist(t, linked)
}

func TestCursorTeardownKeepsALinkedFolderAndReadsNothingBehindIt(t *testing.T) {
	f := useKeptFixture(t, true, func(f keptFixture) []string { return []string{f.cursor} })
	// What a user's junction target could hold: a hooks file and a state file.
	plant(t, filepath.Join(f.cursor, windowsCursorManagedHooksFile), `{"hooks":{}}`)
	plant(t, filepath.Join(f.cursor, windowsCursorManagedStateFile), `not DefenseClaw state`)
	artifacts, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil || artifacts.hooks.existed || artifacts.state.existed || artifacts.receipt.existed {
		t.Fatalf("snapshot behind a link: %+v, err %v; want every artifact absent and no error", artifacts, err)
	}
	var persisted int
	for name, call := range map[string]func() error{
		"publish an empty enrollment": func() error { return PublishWindowsCursorManagedPolicyTargets(nil) },
		"deactivate":                  DeactivateWindowsCursorManagedPolicy,
		"purge the tombstone":         PurgeWindowsCursorManagedTombstone,
		"verify the teardown":         VerifyWindowsCursorManagedPolicyTeardown,
		"capture": func() error {
			_, err := CaptureWindowsCursorManagedPolicySnapshot(WindowsCursorManagedPolicyTeardownOptions{})
			return err
		},
		"prepare the teardown": func() error {
			_, err := PrepareWindowsCursorManagedPolicyTeardown(WindowsCursorManagedPolicyTeardownOptions{},
				func(WindowsCursorManagedPolicyTeardownSnapshot) error { persisted++; return nil })
			return err
		},
		"restore an empty snapshot": func() error {
			return RestoreWindowsCursorManagedPolicyTeardown(WindowsCursorManagedPolicyTeardownOptions{}, WindowsCursorManagedPolicyTeardownSnapshot{})
		},
	} {
		if err := call(); err != nil {
			t.Errorf("%s over a linked Cursor folder: %v", name, err)
		}
	}
	if persisted != 1 {
		t.Errorf("the teardown journal was persisted %d times, want once", persisted)
	}
	if paths, err := WindowsCursorManagedTombstoneFilePaths(); err != nil || len(paths) != 0 {
		t.Errorf("tombstone paths behind a link = %q, err %v; want none", paths, err)
	}
	if _, _, err := ReadWindowsCursorManagedPolicyTargets(); err != nil {
		t.Errorf("read targets behind a link: %v", err)
	}
	if !slices.Equal(WindowsManagedPolicyFoldersKept(), []string{f.cursor}) {
		t.Errorf("kept = %q, want just %s", WindowsManagedPolicyFoldersKept(), f.cursor)
	}
	// Nothing was created, changed or recorded; the planted files are as they were.
	mustExist(t, filepath.Join(f.cursor, windowsCursorManagedHooksFile))
	mustNotExist(t, filepath.Join(f.cursor, windowsCursorManagedLockFile))
	if data, _ := os.ReadFile(filepath.Join(f.cursor, windowsCursorManagedStateFile)); string(data) != "not DefenseClaw state" {
		t.Errorf("the state file behind the link changed: %q", data)
	}
	if len(*f.recorded) != 0 {
		t.Errorf("a created-folder record was written: %q", *f.recorded)
	}
}

func TestCursorTeardownCreatesNothingWhenTheFolderIsAbsent(t *testing.T) {
	f := useKeptFixture(t, true, nil)
	if err := PublishWindowsCursorManagedPolicyTargets(nil); err != nil {
		t.Fatalf("publish an empty enrollment with no Cursor folder: %v", err)
	}
	if err := DeactivateWindowsCursorManagedPolicy(); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureWindowsCursorManagedPolicySnapshot(WindowsCursorManagedPolicyTeardownOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := PurgeWindowsCursorManagedTombstone(); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, f.cursor)
	if len(*f.recorded) != 0 {
		t.Errorf("a created-folder record was written: %q", *f.recorded)
	}
	if kept := WindowsManagedPolicyFoldersKept(); len(kept) != 0 {
		t.Errorf("an absent folder was reported kept: %q", kept)
	}
}

func TestCursorWriteSideStillRefusesALinkAndSecureClientIsUnchanged(t *testing.T) {
	// Install, ensure and repair take the write-side transaction, which refuses.
	f := useKeptFixture(t, true, func(f keptFixture) []string { return []string{f.cursor} })
	err := withWindowsCursorManagedTransaction(func() error { t.Fatal("the write-side transaction ran over a link"); return nil })
	if err == nil || !strings.Contains(err.Error(), "reparse point in path") {
		t.Fatalf("write-side transaction over a link = %v, want the reparse refusal", err)
	}
	// Secure Client keeps its earlier preparation for every call, teardown included.
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	err = PublishWindowsCursorManagedPolicyTargets(nil)
	if err == nil || !strings.Contains(err.Error(), "reparse point in path") {
		t.Fatalf("Secure Client publish over a link = %v, want the earlier refusal", err)
	}
	if kept := WindowsManagedPolicyFoldersKept(); len(kept) != 0 {
		t.Errorf("Secure Client reported a kept folder: %q", kept)
	}
	mustNotExist(t, f.cursor)
}

func TestClaudeTeardownKeepsALinkedFolderAndCreatesNothingWhenAbsent(t *testing.T) {
	sid, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	f := useKeptFixture(t, true, func(f keptFixture) []string { return []string{f.claudeDir} })
	plant(t, filepath.Join(f.claudeDir, windowsClaudeManagedPolicyFile), `{"policy":"behind the link"}`)
	plant(t, filepath.Join(f.claudeDir, windowsClaudeManagedStateFile), `behind the link`)
	if err := removeWindowsClaudeManagedPolicyTarget(sid); err != nil {
		t.Errorf("remove a target behind a link: %v", err)
	}
	if targets, active, err := ReadWindowsClaudeManagedPolicyTargets(); err != nil || active || len(targets) != 0 {
		t.Errorf("read behind a link = %q %v %v, want inactive and no error", targets, active, err)
	}
	if err := PublishWindowsClaudeManagedPolicyTargets(nil); err != nil {
		t.Errorf("publish an empty enrollment behind a link: %v", err)
	}
	if err := PublishWindowsClaudeManagedPolicyTargets([]string{sid.String()}); err == nil {
		t.Error("publishing a target behind a link succeeded; there is no verified policy to enroll it in")
	}
	if err := DeactivateWindowsClaudeManagedPolicy(); err != nil {
		t.Errorf("deactivate behind a link: %v", err)
	}
	if !slices.Equal(WindowsManagedPolicyFoldersKept(), []string{f.claudeDir}) {
		t.Errorf("kept = %q, want just %s", WindowsManagedPolicyFoldersKept(), f.claudeDir)
	}
	mustExist(t, filepath.Join(f.claudeDir, windowsClaudeManagedPolicyFile))
	mustNotExist(t, filepath.Join(f.claudeDir, windowsClaudeManagedLockFile))
	if len(*f.recorded) != 0 {
		t.Errorf("a created-folder record was written: %q", *f.recorded)
	}

	// Absent: nothing is created either (before, the teardown made the folders
	// and recorded them as DefenseClaw's).
	g := useKeptFixture(t, true, nil)
	if err := removeWindowsClaudeManagedPolicyTarget(sid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadWindowsClaudeManagedPolicyTargets(); err != nil {
		t.Fatal(err)
	}
	if err := PublishWindowsClaudeManagedPolicyTargets(nil); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, g.claudeDir)
	mustNotExist(t, filepath.Dir(g.claudeDir))
	if len(*g.recorded) != 0 {
		t.Errorf("a created-folder record was written: %q", *g.recorded)
	}

	// Secure Client: the earlier preparation, which refuses the link.
	h := useKeptFixture(t, false, func(f keptFixture) []string { return []string{f.claudeDir} })
	if err := removeWindowsClaudeManagedPolicyTarget(sid); err == nil || !strings.Contains(err.Error(), "reparse point in path") {
		t.Errorf("Secure Client remove over a link = %v, want the earlier refusal", err)
	}
	mustNotExist(t, h.claudeDir)
}

func TestSelectorAndPerUserTeardownKeepALinkedFolder(t *testing.T) {
	f := useKeptFixture(t, true, func(f keptFixture) []string { return []string{f.selectorDir, f.perUserDir} })
	plant(t, filepath.Join(f.selectorDir, windowsManagedRuntimeSelectorFile), `behind the link`)
	plant(t, filepath.Join(f.selectorDir, windowsManagedRuntimeSelectorLockFile), `behind the link`)
	ran := 0
	if err := withWindowsManagedRuntimeSelectorTeardownTransaction("codex", func() error { ran++; return nil }); err != nil || ran != 0 {
		t.Errorf("selector teardown over a link: ran %d times, err %v; want it skipped", ran, err)
	}
	if err := RemoveWindowsStandaloneMachinePolicySelectorLocks(); err != nil {
		t.Errorf("selector lock removal over a link: %v", err)
	}
	if err := RemoveWindowsStandaloneDeletedAccountSelectorTargets(); err != nil {
		t.Errorf("deleted-account selector cleanup over a link: %v", err)
	}
	mustExist(t, filepath.Join(f.selectorDir, windowsManagedRuntimeSelectorFile))
	mustExist(t, filepath.Join(f.selectorDir, windowsManagedRuntimeSelectorLockFile))
	if present, err := windowsPerUserManagedRuntimeDirPresent("copilot"); err != nil || present {
		t.Errorf("per-user folder behind a link: present %v, err %v; want not present", present, err)
	}
	if err := RemoveWindowsPerUserManagedEnrollments(`C:\hook.exe`, []string{"copilot"}); err != nil {
		t.Errorf("per-user enrollment revoke over a link: %v", err)
	}

	// Absent: no selector folder is made, no lock taken.
	g := useKeptFixture(t, true, nil)
	if err := withWindowsManagedRuntimeSelectorTeardownTransaction("codex", func() error { ran++; return nil }); err != nil || ran != 1 {
		t.Errorf("selector teardown with no folder: ran %d times, err %v; want it run once", ran, err)
	}
	mustNotExist(t, g.selectorDir)
	if len(*g.recorded) != 0 {
		t.Errorf("a created-folder record was written: %q", *g.recorded)
	}
}

// GAP-0773 and GAP-0829: the teardown's comparison of what the manifest says is
// enrolled with what it reads must leave a connector out when a link keeps its
// machine folder. WindowsManagedConnectorFolderKept answers per connector.
func TestWindowsManagedConnectorFolderKept(t *testing.T) {
	folders := func(f keptFixture) map[string]string {
		root := filepath.Dir(filepath.Dir(f.cursor))
		return map[string]string{
			"cursor":     f.cursor,
			"claudecode": f.claudeDir,
			"codex":      f.selectorDir,
			"copilot":    f.perUserDir,
			"opencode":   filepath.Join(root, "runtime", "opencode"),
			"devin":      filepath.Join(root, "runtime", "devin"),
		}
	}
	for _, connectorName := range []string{"cursor", "claudecode", "codex", "copilot", "opencode", "devin"} {
		t.Run(connectorName, func(t *testing.T) {
			f := useKeptFixture(t, true, nil)
			dirs := folders(f)
			windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
				return filepath.Join(dirs[name], windowsManagedRuntimeSelectorFile), nil
			}
			// Absent and plain folders are not kept.
			if kept, err := WindowsManagedConnectorFolderKept(connectorName); err != nil || kept != "" {
				t.Fatalf("absent folder: kept=%q err=%v", kept, err)
			}
			if err := os.MkdirAll(dirs[connectorName], 0o700); err != nil {
				t.Fatal(err)
			}
			if kept, err := WindowsManagedConnectorFolderKept(connectorName); err != nil || kept != "" {
				t.Fatalf("plain folder: kept=%q err=%v", kept, err)
			}
			if len(WindowsManagedPolicyFoldersKept()) != 0 {
				t.Fatalf("a plain folder was named kept: %v", WindowsManagedPolicyFoldersKept())
			}
			// A link at the folder keeps it; the link is named once.
			windowsReparseChainProbe = linkProbe(dirs[connectorName])
			for i := 0; i < 2; i++ {
				kept, err := WindowsManagedConnectorFolderKept(connectorName)
				if err != nil || !strings.EqualFold(kept, dirs[connectorName]) {
					t.Fatalf("link at the folder: kept=%q err=%v", kept, err)
				}
			}
			if named := WindowsManagedPolicyFoldersKept(); len(named) != 1 || !strings.EqualFold(named[0], dirs[connectorName]) {
				t.Fatalf("the link was not named exactly once: %v", named)
			}
			// A link on a parent keeps it too, and names the link itself.
			parent := filepath.Dir(dirs[connectorName])
			windowsReparseChainProbe = linkProbe(parent)
			if kept, err := WindowsManagedConnectorFolderKept(connectorName); err != nil || !strings.EqualFold(kept, parent) {
				t.Fatalf("link above the folder: kept=%q err=%v", kept, err)
			}
			// A link at another connector's folder does not keep this one.
			for other, dir := range dirs {
				if other == connectorName || strings.HasPrefix(strings.ToLower(dirs[connectorName]), strings.ToLower(dir)+`\`) {
					continue
				}
				windowsReparseChainProbe = linkProbe(dir)
				if kept, err := WindowsManagedConnectorFolderKept(connectorName); err != nil || kept != "" {
					t.Fatalf("a link at %s kept %s: %q err=%v", other, connectorName, kept, err)
				}
			}
		})
	}
	t.Run("a file where the folder belongs is kept", func(t *testing.T) {
		f := useKeptFixture(t, true, nil)
		plant(t, f.cursor, "not a folder")
		windowsManagedRuntimeSelectorPathResolver = func(string) (string, error) {
			return filepath.Join(f.cursor, windowsManagedRuntimeSelectorFile), nil
		}
		if kept, err := WindowsManagedConnectorFolderKept("cursor"); err != nil || !strings.EqualFold(kept, f.cursor) {
			t.Fatalf("file at the folder: kept=%q err=%v", kept, err)
		}
	})
	t.Run("Secure Client keeps its comparison", func(t *testing.T) {
		useKeptFixture(t, false, func(f keptFixture) []string { return []string{f.cursor, f.selectorDir, f.claudeDir, f.perUserDir} })
		for _, name := range []string{"cursor", "claudecode", "codex", "copilot"} {
			if kept, err := WindowsManagedConnectorFolderKept(name); err != nil || kept != "" {
				t.Fatalf("Secure Client %s: kept=%q err=%v", name, kept, err)
			}
		}
	})
}

// GAP-0829: an enrolled Cursor account is not a missing policy when a link
// keeps the folder. The teardown's capture and prepare read the folder as
// empty and go on; without the link the same call still refuses, and a link
// at another connector's folder does not excuse it.
func TestCursorTeardownWithAnEnrolledTargetKeepsALinkedFolder(t *testing.T) {
	enrolled := WindowsCursorManagedPolicyTeardownOptions{Targets: []WindowsCursorManagedRuntimeTarget{{
		SID: "S-1-5-21-1-2-3-1017", DataDir: `C:\Users\alice\.defenseclaw`,
	}}}
	f := useKeptFixture(t, true, func(f keptFixture) []string { return []string{f.cursor} })
	plant(t, filepath.Join(f.cursor, windowsCursorManagedStateFile), `not DefenseClaw state`)
	persisted := 0
	snapshot, err := PrepareWindowsCursorManagedPolicyTeardown(enrolled,
		func(WindowsCursorManagedPolicyTeardownSnapshot) error { persisted++; return nil })
	if err != nil || persisted != 1 || snapshot.PolicyActive {
		t.Fatalf("prepare with an enrolled target behind a link: err %v, persisted %d, snapshot %+v; want an empty snapshot persisted once", err, persisted, snapshot)
	}
	if snapshot, err = CaptureWindowsCursorManagedPolicySnapshot(enrolled); err != nil || snapshot.PolicyActive {
		t.Fatalf("capture with an enrolled target behind a link: err %v, snapshot %+v", err, snapshot)
	}
	if data, _ := os.ReadFile(filepath.Join(f.cursor, windowsCursorManagedStateFile)); string(data) != "not DefenseClaw state" {
		t.Errorf("the file behind the link changed: %q", data)
	}

	// No link: an enrolled target with no policy is a mismatch and still refuses.
	useKeptFixture(t, true, nil)
	if _, err := PrepareWindowsCursorManagedPolicyTeardown(enrolled, func(WindowsCursorManagedPolicyTeardownSnapshot) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "expected Cursor managed policy is absent") {
		t.Errorf("prepare with an enrolled target and no policy = %v, want the refusal", err)
	}
	if _, err := CaptureWindowsCursorManagedPolicySnapshot(enrolled); err == nil ||
		!strings.Contains(err.Error(), "expected Cursor managed policy is absent") {
		t.Errorf("capture with an enrolled target and no policy = %v, want the refusal", err)
	}
	// A link at the Claude Code folder does not excuse Cursor.
	useKeptFixture(t, true, func(f keptFixture) []string { return []string{f.claudeDir} })
	if _, err := PrepareWindowsCursorManagedPolicyTeardown(enrolled, func(WindowsCursorManagedPolicyTeardownSnapshot) error { return nil }); err == nil {
		t.Error("a link at the Claude Code folder excused a Cursor mismatch")
	}
}
