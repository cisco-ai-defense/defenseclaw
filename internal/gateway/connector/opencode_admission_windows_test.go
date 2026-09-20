// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const openCodeAdmissionTestRawVersion = "1.18.19"

func TestOpenCodeProtectedLockPersistsExactAuthorityAfterReceiptRemoval(t *testing.T) {
	opts := prepareOpenCodeSetupAdmissionFixture(t)
	entry := NewHookContractLockEntry(opts, NewOpenCodeConnector(), "test-build")
	if !validSetupSelectedAgentExecutableEvidence(entry, "opencode") {
		t.Fatalf("new OpenCode lock lacks executable evidence: %+v", entry)
	}
	if err := SaveFreshHookContractLockEntry(opts.DataDir, entry); err != nil {
		t.Fatalf("seal fresh OpenCode receipt: %v", err)
	}
	if err := os.Remove(filepath.Join(opts.DataDir, agentSelectionFile)); err != nil {
		t.Fatal(err)
	}

	if got := LoadCachedAgentVersion(opts.DataDir, "opencode"); got != opts.AgentVersion {
		t.Fatalf("locked OpenCode version = %q, want %q", got, opts.AgentVersion)
	}
	if got := LoadCachedAgentExecutable(opts.DataDir, "opencode"); !sameCodexExecutablePath(got, opts.AgentExecutable) {
		t.Fatalf("locked OpenCode executable = %q, want %q", got, opts.AgentExecutable)
	}
	if err := validateOpenCodeWindowsSetupAdmission(opts); err != nil {
		t.Fatalf("reuse intact sealed OpenCode authority: %v", err)
	}
	if refreshed := NewHookContractLockEntry(opts, NewOpenCodeConnector(), "test-build"); validateOpenCodeWindowsLockPublication(opts.DataDir, refreshed) != nil {
		t.Fatalf("republish intact sealed OpenCode authority: %v", validateOpenCodeWindowsLockPublication(opts.DataDir, refreshed))
	}
}

func TestOpenCodeContractPublicationRejectsReplacementAfterSelection(t *testing.T) {
	opts := prepareOpenCodeSetupAdmissionFixture(t)
	if err := atomicWriteFile(opts.AgentExecutable, []byte("MZ replacement OpenCode bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry := NewHookContractLockEntry(opts, NewOpenCodeConnector(), "test-build")
	lockPath := filepath.Join(opts.DataDir, hookContractLockFile)
	if err := SaveFreshHookContractLockEntry(opts.DataDir, entry); err == nil ||
		!strings.Contains(err.Error(), "does not match protected executable evidence") {
		t.Fatalf("replacement publication error = %v, want protected-evidence mismatch", err)
	}
	if _, err := os.Lstat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("failed publication created a contract lock: %v", err)
	}
}

func TestOpenCodeSealedAuthorityRejectsLaterExecutableDrift(t *testing.T) {
	opts := prepareOpenCodeSetupAdmissionFixture(t)
	entry := NewHookContractLockEntry(opts, NewOpenCodeConnector(), "test-build")
	if err := SaveFreshHookContractLockEntry(opts.DataDir, entry); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(opts.DataDir, agentSelectionFile)); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(opts.AgentExecutable, []byte("MZ changed after OpenCode lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateOpenCodeWindowsSetupAdmission(opts); err == nil ||
		!strings.Contains(err.Error(), "digest does not match protected evidence") {
		t.Fatalf("changed OpenCode image admission error = %v, want digest refusal", err)
	}
}

func TestOpenCodeLegacyUnsealedLockCannotReplaceExpiredReceipt(t *testing.T) {
	opts := prepareOpenCodeSetupAdmissionFixture(t)
	entry := NewHookContractLockEntry(opts, NewOpenCodeConnector(), "test-build")
	entry.AgentExecutable = ""
	entry.AgentExecutableSource = ""
	entry.AgentExecutableSHA256 = ""
	lock := hookContractLock{
		Version:    hookContractLockVersion,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		Connectors: map[string]HookContractLockEntry{"opencode": entry},
	}
	body, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(opts.DataDir, hookContractLockFile), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(opts.DataDir, agentSelectionFile)); err != nil {
		t.Fatal(err)
	}
	if got := LoadCachedAgentVersion(opts.DataDir, "opencode"); got != "" {
		t.Fatalf("legacy OpenCode lock returned version %q", got)
	}
	if got := LoadCachedAgentExecutable(opts.DataDir, "opencode"); got != "" {
		t.Fatalf("legacy OpenCode lock returned executable %q", got)
	}
	if err := validateOpenCodeWindowsSetupAdmission(opts); err == nil ||
		!strings.Contains(err.Error(), "contract lock executable evidence is invalid") {
		t.Fatalf("legacy OpenCode admission error = %v", err)
	}
}

func prepareOpenCodeSetupAdmissionFixture(t *testing.T) SetupOpts {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	return prepareOpenCodeSetupOptsForTest(t, SetupOpts{DataDir: filepath.Join(root, "defenseclaw-data")})
}

func prepareOpenCodeSetupOptsForTest(t *testing.T, opts SetupOpts) SetupOpts {
	t.Helper()
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = filepath.Join(testenv.PrivateTempDir(t), "defenseclaw-data")
	}
	if err := ensureManagedBackupDirRestricted(dataDir); err != nil {
		t.Fatalf("protect OpenCode admission data directory: %v", err)
	}
	root := testenv.PrivateTempDir(t)
	executable := filepath.Join(
		root,
		"LocalAppData",
		"Microsoft",
		"WinGet",
		"Packages",
		openCodeWindowsPackageDirectory,
		"opencode.exe",
	)
	if err := atomicWriteFile(executable, []byte("MZ OpenCode 1.18.19 admission fixture"), 0o700); err != nil {
		t.Fatalf("write OpenCode admission executable: %v", err)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("hash OpenCode admission executable")
	}
	now := time.Now().UTC().Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"opencode": {
				Connector:         "opencode",
				Source:            "setup-selected",
				Executable:        stablePath,
				RawVersion:        openCodeAdmissionTestRawVersion,
				NormalizedVersion: "1.18.19",
				SHA256:            digest,
				SelectedAt:        now.Add(-time.Second).Format(time.RFC3339),
				ExpiresAt:         now.Add(10 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dataDir, agentSelectionFile), append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write protected OpenCode selection receipt: %v", err)
	}
	if _, ok := loadSetupAgentSelection(dataDir, "opencode"); !ok {
		t.Fatal("OpenCode admission fixture did not produce a valid protected receipt")
	}
	previousResolver := openCodeWindowsExecutablePathResolver
	openCodeWindowsExecutablePathResolver = func() string { return stablePath }
	t.Cleanup(func() { openCodeWindowsExecutablePathResolver = previousResolver })
	opts.DataDir = dataDir
	opts.AgentVersion = openCodeAdmissionTestRawVersion
	opts.AgentExecutable = stablePath
	opts.HookContractID = "opencode-hooks-v1"
	return opts
}
