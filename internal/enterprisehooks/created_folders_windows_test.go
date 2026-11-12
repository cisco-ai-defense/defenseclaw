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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type createdFolderFixture struct {
	programFiles, programData, lifecycle, records string
}

// useCreatedFolderFixture points the created-folder record at a scratch
// ProgramData and Program Files with an existing lifecycle folder.
func useCreatedFolderFixture(t *testing.T, standalone bool, trust func(string) error) createdFolderFixture {
	t.Helper()
	base := t.TempDir()
	fixture := createdFolderFixture{
		programFiles: filepath.Join(base, "Program Files"),
		programData:  filepath.Join(base, "ProgramData"),
	}
	fixture.lifecycle = filepath.Join(fixture.programData, "Cisco", "DefenseClaw-Lifecycle")
	fixture.records = filepath.Join(fixture.lifecycle, windowsCreatedFolderRecordDirName)
	for _, dir := range []string{fixture.programFiles, fixture.lifecycle} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previousRoots, previousStandalone, previousTrust := windowsCreatedFolderRoots, windowsEnterpriseStandaloneProcess, windowsManagedPolicyAncestorTrustCheck
	t.Cleanup(func() {
		windowsCreatedFolderRoots, windowsEnterpriseStandaloneProcess, windowsManagedPolicyAncestorTrustCheck = previousRoots, previousStandalone, previousTrust
	})
	windowsCreatedFolderRoots = func() (string, string, string, error) {
		return fixture.programFiles, fixture.programData, fixture.lifecycle, nil
	}
	windowsEnterpriseStandaloneProcess = func() bool { return standalone }
	windowsManagedPolicyAncestorTrustCheck = trust
	return fixture
}

func trustAll(string) error { return nil }

func readCreatedFolderRecords(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var record windowsCreatedFolderRecord
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatalf("record %s: %v (%s)", entry.Name(), err, data)
		}
		if record.SchemaVersion != 1 {
			t.Fatalf("record %s schema = %d, want 1", entry.Name(), record.SchemaVersion)
		}
		records[entry.Name()] = record.Path
	}
	return records
}

// GAP-0091: each folder a writer created under ProgramData or Program Files
// gets one write-once record, named by the SHA-256 of its path with ASCII
// letters in lower case (the lifecycle's Get-DefenseClawCreatedFolderRecordName).
// Nothing outside those roots, and never a root itself.
func TestStandaloneCreatedFolderRecordNamesEachCreatedVendorFolderOnce(t *testing.T) {
	fixture := useCreatedFolderFixture(t, true, trustAll)
	cursor := filepath.Join(fixture.programData, "Cursor")
	codex := filepath.Join(fixture.programData, "OpenAI", "Codex")
	claude := filepath.Join(fixture.programFiles, "ClaudeCode", "managed-settings.d")
	outside := filepath.Join(filepath.Dir(fixture.programData), "Elsewhere")
	if err := recordWindowsCreatedFolders([]string{cursor, codex, claude, outside, fixture.programData, "relative"}); err != nil {
		t.Fatal(err)
	}
	if err := recordWindowsCreatedFolders([]string{strings.ToUpper(cursor)}); err != nil {
		t.Fatal(err)
	}
	records := readCreatedFolderRecords(t, fixture.records)
	if len(records) != 3 {
		t.Fatalf("records = %v, want Cursor, OpenAI\\Codex and ClaudeCode\\managed-settings.d only", records)
	}
	for _, path := range []string{cursor, codex, claude} {
		sum := sha256.Sum256([]byte(strings.ToLower(path)))
		name := hex.EncodeToString(sum[:]) + ".json"
		if records[name] != path {
			t.Fatalf("record %s = %q, want %q", name, records[name], path)
		}
	}
}

// GAP-0091 review L3: the record name folds only A-Z, the same on both
// sides. The lifecycle smoke (enterprise-standalone-machine-leftovers-purge-smoke.ps1)
// pins the same name for the same path, so a non-ASCII vendor folder the
// hooks record is a record the lifecycle accepts.
func TestStandaloneCreatedFolderRecordNameFoldsOnlyASCIILetters(t *testing.T) {
	const path = "C:\\ProgramData\\\u00dcn\u00efcode \u0130\\Codex"
	const want = "cb0ed1e34f5e1961147f1101c3b7a237146fc893cc261ebfaaadb52ada704767.json"
	if got := windowsCreatedFolderRecordName(path); got != want {
		t.Fatalf("record name of %q = %s, want %s", path, got, want)
	}
	if got := windowsCreatedFolderRecordName("c:\\PROGRAMDATA\\\u00dcN\u00efCODE \u0130\\codex"); got != want {
		t.Fatalf("an ASCII case change renamed the record: %s", got)
	}
	// A full Unicode fold would map U+0130 and U+00DC and give another name.
	if got := windowsCreatedFolderRecordName(strings.ToLower(path)); got == want {
		t.Fatal("non-ASCII letters were folded")
	}
}

// The lifecycle creates its folder; a writer never does (that would create
// C:\ProgramData\Cisco without a record). Secure Client keeps no record, and
// an untrusted lifecycle folder gets none.
func TestStandaloneCreatedFolderRecordNeedsTheTrustedStandaloneLifecycleFolder(t *testing.T) {
	t.Run("secure client", func(t *testing.T) {
		fixture := useCreatedFolderFixture(t, false, trustAll)
		if err := recordWindowsCreatedFolders([]string{filepath.Join(fixture.programData, "Cursor")}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(fixture.records); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Secure Client wrote a created-folder record: %v", err)
		}
	})
	t.Run("no lifecycle folder", func(t *testing.T) {
		fixture := useCreatedFolderFixture(t, true, trustAll)
		if err := os.Remove(fixture.lifecycle); err != nil {
			t.Fatal(err)
		}
		if err := recordWindowsCreatedFolders([]string{filepath.Join(fixture.programData, "Cursor")}); err == nil {
			t.Fatal("recorded without a lifecycle folder")
		}
		if _, err := os.Lstat(fixture.lifecycle); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the writer created the lifecycle folder: %v", err)
		}
	})
	t.Run("untrusted lifecycle folder", func(t *testing.T) {
		fixture := useCreatedFolderFixture(t, true, func(path string) error {
			return errors.New("untrusted principal S-1-5-32-545 has write access")
		})
		if err := recordWindowsCreatedFolders([]string{filepath.Join(fixture.programData, "Cursor")}); err == nil {
			t.Fatal("recorded into an untrusted lifecycle folder")
		}
		if _, err := os.Lstat(fixture.records); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a record folder was created in an untrusted lifecycle folder: %v", err)
		}
	})
}

// ensureWindowsManagedPolicyDirectory records exactly the folders it
// created: never the existing vendor folder above them, and nothing on a
// second call that creates nothing.
func TestEnsureWindowsManagedPolicyDirectoryRecordsOnlyTheFoldersItCreated(t *testing.T) {
	previousDir, previousAncestor, previousRecorder := windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck, windowsCreatedFolderRecorder
	t.Cleanup(func() {
		windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck, windowsCreatedFolderRecorder = previousDir, previousAncestor, previousRecorder
	})
	windowsManagedPolicyDirTrustCheck = trustAll
	windowsManagedPolicyAncestorTrustCheck = trustAll
	var recorded [][]string
	windowsCreatedFolderRecorder = func(created []string) error {
		recorded = append(recorded, append([]string(nil), created...))
		return nil
	}
	existing := filepath.Join(t.TempDir(), "OpenAI")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	codex := filepath.Join(existing, "Codex")
	leaf := filepath.Join(codex, "hooks")
	if err := ensureWindowsManagedPolicyDirectory(leaf); err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsManagedPolicyDirectory(leaf); err != nil {
		t.Fatal(err)
	}
	// The second call finds every folder present and records nothing.
	if len(recorded) != 1 || !slices.Equal(recorded[0], []string{codex, leaf}) {
		t.Fatalf("recorded = %q, want [[%s %s]]", recorded, codex, leaf)
	}
}

// GAP-0091 review 2 S1: a failed Claude Code publish leaves each folder the
// install created together with its record. The transaction creates and
// records managed-settings.d and ClaudeCode before it takes its lock file in
// there, so the publish creates nothing and its rollback removes no folder:
// a record never outlives its folder, and a purge removes both once empty.
// Run with the real transaction lock and with the publish alone (the
// transaction stubbed, as the other install tests do, so the publish's own
// folder step creates them).
func TestClaudePublishRollbackKeepsEachCreatedFolderWithItsRecord(t *testing.T) {
	for _, realLock := range []bool{true, false} {
		name := "publish alone"
		if realLock {
			name = "real transaction lock"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newWindowsManagedInstallFixture(t, nil)
			policyDir := filepath.Dir(fixture.policyPath)
			policyRoot := filepath.Dir(policyDir)
			for _, dir := range []string{policyDir, policyRoot} {
				if err := os.Remove(dir); err != nil {
					t.Fatal(err)
				}
			}
			previousTransaction, previousRecorder, previousWriter := windowsClaudeManagedPolicyTransaction, windowsCreatedFolderRecorder, windowsManagedPolicyWriter
			t.Cleanup(func() {
				windowsClaudeManagedPolicyTransaction, windowsCreatedFolderRecorder, windowsManagedPolicyWriter = previousTransaction, previousRecorder, previousWriter
			})
			if realLock {
				windowsClaudeManagedPolicyTransaction = withWindowsClaudeManagedPolicyTransaction
			}
			recorded := map[string]bool{}
			windowsCreatedFolderRecorder = func(created []string) error {
				for _, folder := range created {
					recorded[strings.ToLower(filepath.Clean(folder))] = true
				}
				return nil
			}
			windowsManagedPolicyWriter = func(path string, data []byte, readable bool) error {
				if filepath.Base(path) == windowsClaudeManagedStateFile {
					return errors.New("injected state publication failure")
				}
				return writeWindowsManagedFile(path, data, readable)
			}
			_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
			if err == nil || !strings.Contains(err.Error(), "injected state publication failure") {
				t.Fatalf("Install error = %v, want the injected publish failure", err)
			}
			for _, path := range []string{fixture.policyPath, filepath.Join(policyDir, windowsClaudeManagedStateFile)} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the rollback left %s: %v", path, err)
				}
			}
			for _, dir := range []string{policyRoot, policyDir} {
				if _, err := os.Lstat(dir); err != nil {
					t.Fatalf("created folder %s after the rollback: %v", dir, err)
				}
				if !recorded[strings.ToLower(dir)] {
					t.Fatalf("created folder %s has no record (records: %v)", dir, recorded)
				}
			}
			if len(recorded) != 2 {
				t.Fatalf("records = %v, want ClaudeCode and managed-settings.d only", recorded)
			}
		})
	}
}

// GAP-0091 review 2 S1: DefenseClaw's own folders in the Cisco folders are
// not recorded: the purge and the hooks' teardown remove them with the
// deployment, so a record of one would outlive it. The Cisco folder itself
// is.
func TestStandaloneCreatedFolderRecordSkipsDefenseClawsOwnFolders(t *testing.T) {
	fixture := useCreatedFolderFixture(t, true, trustAll)
	vendor := filepath.Join(fixture.programData, "Cisco")
	own := []string{
		filepath.Join(vendor, "DefenseClaw-HookRuntime"),
		filepath.Join(vendor, "DefenseClaw-HookRuntime", "opencode"),
		filepath.Join(fixture.programFiles, "Cisco", "DefenseClaw", "bin"),
		filepath.Join(vendor, "defenseclaw-mdm"),
	}
	if err := recordWindowsCreatedFolders(append(own, vendor, filepath.Join(vendor, "DefenseClawOther"))); err != nil {
		t.Fatal(err)
	}
	records := readCreatedFolderRecords(t, fixture.records)
	if len(records) != 2 || records[windowsCreatedFolderRecordName(vendor)] != vendor ||
		records[windowsCreatedFolderRecordName(filepath.Join(vendor, "DefenseClawOther"))] == "" {
		t.Fatalf("records = %v, want only %s and Cisco\\DefenseClawOther (not a DefenseClaw folder name)", records, vendor)
	}
}

// GAP-0091 review 2 S1: the CLI's removal of C:\Program Files\Cisco removes
// only a recorded, empty, trusted plain folder, and takes its record with it.
func TestRemoveWindowsCreatedFolderIfEmptyTakesTheRecordWithTheFolder(t *testing.T) {
	realStandaloneProcess := windowsEnterpriseStandaloneProcess
	previousFileTrust := windowsManagedPolicyFileTrustCheck
	t.Cleanup(func() { windowsManagedPolicyFileTrustCheck = previousFileTrust })
	windowsManagedPolicyFileTrustCheck = trustAll
	fixture := useCreatedFolderFixture(t, true, trustAll)
	folder := filepath.Join(fixture.programFiles, "Cisco")
	record := filepath.Join(fixture.records, windowsCreatedFolderRecordName(folder))
	reset := func(t *testing.T, recordIt bool, content string) {
		t.Helper()
		_ = os.RemoveAll(folder)
		_ = os.Remove(record)
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		if content != "" {
			if err := os.WriteFile(filepath.Join(folder, content), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if recordIt {
			if err := recordWindowsCreatedFolders([]string{folder}); err != nil {
				t.Fatal(err)
			}
		}
	}
	exists := func(path string) bool {
		_, err := os.Lstat(path)
		return err == nil
	}

	reset(t, true, "")
	if removed, err := RemoveWindowsCreatedFolderIfEmpty(folder); err != nil || !removed || exists(folder) || exists(record) {
		t.Fatalf("recorded empty folder: removed=%v err=%v folder=%v record=%v, want both gone", removed, err, exists(folder), exists(record))
	}
	reset(t, true, "other-product.txt")
	if removed, err := RemoveWindowsCreatedFolderIfEmpty(folder); err != nil || removed || !exists(folder) || !exists(record) {
		t.Fatalf("recorded folder holding a file: removed=%v err=%v, want both kept", removed, err)
	}
	reset(t, false, "")
	if removed, err := RemoveWindowsCreatedFolderIfEmpty(folder); err != nil || removed || !exists(folder) {
		t.Fatalf("a folder that existed before the install (no record): removed=%v err=%v, want kept", removed, err)
	}
	t.Run("untrusted folder", func(t *testing.T) {
		reset(t, true, "")
		windowsManagedPolicyAncestorTrustCheck = func(path string) error {
			if strings.EqualFold(path, folder) {
				return errors.New("untrusted owner")
			}
			return nil
		}
		t.Cleanup(func() { windowsManagedPolicyAncestorTrustCheck = trustAll })
		if removed, err := RemoveWindowsCreatedFolderIfEmpty(folder); err == nil || removed || !exists(folder) || !exists(record) {
			t.Fatalf("untrusted folder: removed=%v err=%v, want both kept with an error", removed, err)
		}
	})
	t.Run("junction at the recorded folder", func(t *testing.T) {
		reset(t, true, "")
		if err := os.Remove(folder); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		makeTestJunction(t, folder, target)
		t.Cleanup(func() { _ = os.Remove(folder) })
		if removed, err := RemoveWindowsCreatedFolderIfEmpty(folder); err == nil || removed || !exists(target) || !exists(record) {
			t.Fatalf("junction: removed=%v err=%v target=%v record=%v, want refused", removed, err, exists(target), exists(record))
		}
	})
	// Review 3 L2: the CLI that removes the folder after an uninstall carries
	// no standalone profile pin, so the removal must not test one. This row
	// runs the real pin test with the variable unset, as the CLI process
	// does, and removes the folder through its record.
	t.Run("a process without the profile pin removes the recorded folder", func(t *testing.T) {
		reset(t, true, "")
		windowsEnterpriseStandaloneProcess = realStandaloneProcess
		t.Cleanup(func() { windowsEnterpriseStandaloneProcess = func() bool { return true } })
		t.Setenv(managed.EnterpriseProfileEnv, "")
		if realStandaloneProcess() {
			t.Fatal("the process pin must be unset for this row")
		}
		if removed, err := RemoveWindowsCreatedFolderIfEmpty(folder); err != nil || !removed || exists(folder) || exists(record) {
			t.Fatalf("no pin: removed=%v err=%v folder=%v record=%v, want both gone", removed, err, exists(folder), exists(record))
		}
	})
	// Review 3 L3: a back-filled record (origin upgrade) is treated like one
	// written at creation; nothing reads the origin.
	t.Run("an upgrade record is removed like any other", func(t *testing.T) {
		reset(t, false, "")
		body, err := json.Marshal(windowsCreatedFolderRecord{SchemaVersion: 1, Path: folder, Origin: "upgrade"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(fixture.records, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(record, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if removed, err := RemoveWindowsCreatedFolderIfEmpty(folder); err != nil || !removed || exists(folder) || exists(record) {
			t.Fatalf("origin upgrade: removed=%v err=%v folder=%v record=%v, want both gone", removed, err, exists(folder), exists(record))
		}
	})
	t.Run("secure client keeps no record, so nothing is removed", func(t *testing.T) {
		reset(t, false, "")
		windowsEnterpriseStandaloneProcess = realStandaloneProcess
		t.Cleanup(func() { windowsEnterpriseStandaloneProcess = func() bool { return true } })
		t.Setenv(managed.EnterpriseProfileEnv, "")
		if removed, err := RemoveWindowsCreatedFolderIfEmpty(folder); err != nil || removed || !exists(folder) {
			t.Fatalf("Secure Client: removed=%v err=%v, want nothing removed", removed, err)
		}
	})
}

// GAP-0758 round 2 (the g091 record-only rule): a purge removes Claude Code's
// managed-settings.d and ClaudeCode folders only when the created-folder
// record names them, an origin:upgrade record included, and never by name.
// The CLI used to remove both by name once they were empty; it now relies on
// this record lookup and its reparse-safe removal alone.
func TestRemoveWindowsCreatedFolderIfEmptyKeepsAnUnrecordedClaudeCodeFolder(t *testing.T) {
	previousFileTrust := windowsManagedPolicyFileTrustCheck
	t.Cleanup(func() { windowsManagedPolicyFileTrustCheck = previousFileTrust })
	windowsManagedPolicyFileTrustCheck = trustAll
	fixture := useCreatedFolderFixture(t, true, trustAll)
	root := filepath.Join(fixture.programFiles, "ClaudeCode")
	dropIns := filepath.Join(root, "managed-settings.d")
	if err := os.MkdirAll(dropIns, 0o700); err != nil {
		t.Fatal(err)
	}
	exists := func(path string) bool {
		_, err := os.Lstat(path)
		return err == nil
	}
	remove := func() {
		for _, folder := range []string{dropIns, root} {
			if _, err := RemoveWindowsCreatedFolderIfEmpty(folder); err != nil {
				t.Fatalf("%s: %v", folder, err)
			}
		}
	}

	// Made by an administrator before the install: no record, so both stay.
	remove()
	if !exists(dropIns) || !exists(root) {
		t.Fatalf("unrecorded empty ClaudeCode folders were removed: drop-ins=%v root=%v", exists(dropIns), exists(root))
	}

	// Recorded by the install (managed-settings.d) and back-filled by the
	// upgrade (ClaudeCode, origin upgrade): both go, and so do their records.
	if err := recordWindowsCreatedFolders([]string{dropIns}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(windowsCreatedFolderRecord{SchemaVersion: 1, Path: root, Origin: "upgrade"})
	if err != nil {
		t.Fatal(err)
	}
	rootRecord := filepath.Join(fixture.records, windowsCreatedFolderRecordName(root))
	if err := os.WriteFile(rootRecord, body, 0o600); err != nil {
		t.Fatal(err)
	}
	remove()
	if exists(dropIns) || exists(root) || exists(rootRecord) || exists(filepath.Join(fixture.records, windowsCreatedFolderRecordName(dropIns))) {
		t.Fatalf("recorded ClaudeCode folders stayed: drop-ins=%v root=%v", exists(dropIns), exists(root))
	}

	// A recorded ClaudeCode folder that holds the administrator's own file stays.
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := recordWindowsCreatedFolders([]string{root}); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(root, "managed-settings.json")
	if err := os.WriteFile(keep, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveWindowsCreatedFolderIfEmpty(root); err != nil || removed || !exists(keep) {
		t.Fatalf("recorded ClaudeCode folder holding a file: removed=%v err=%v kept file=%v", removed, err, exists(keep))
	}
}
