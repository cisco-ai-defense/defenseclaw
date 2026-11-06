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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
// gets one write-once record, named by the SHA-256 of its lower-case path
// (the lifecycle's Get-DefenseClawCreatedFolderRecordName). Nothing outside
// those roots, and never a root itself.
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
	if len(recorded) != 2 || !slices.Equal(recorded[0], []string{codex, leaf}) || len(recorded[1]) != 0 {
		t.Fatalf("recorded = %q, want [[%s %s] []]", recorded, codex, leaf)
	}
}
