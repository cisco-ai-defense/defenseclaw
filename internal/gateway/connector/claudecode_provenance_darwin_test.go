// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeClaudeCodeDarwinFixture(t *testing.T) string {
	t.Helper()
	return writeClaudeCodeDarwinFixtureAt(t, t.TempDir(), "claude")
}

func writeClaudeCodeDarwinFixtureAt(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte("claude")...), 0o500); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestClaudeCodeDarwinSignatureIdentityRequiresExactLines(t *testing.T) {
	valid := "Identifier=com.anthropic.claude-code\n" +
		"Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\n" +
		"TeamIdentifier=Q6L2SF6YDW\n"
	for _, test := range []struct {
		name   string
		detail string
		want   bool
	}{
		{name: "exact", detail: valid, want: true},
		{
			name:   "identifier suffix",
			detail: strings.Replace(valid, "Identifier=com.anthropic.claude-code", "Identifier=com.anthropic.claude-code-helper", 1),
		},
		{
			name:   "team suffix",
			detail: strings.Replace(valid, "TeamIdentifier=Q6L2SF6YDW", "TeamIdentifier=Q6L2SF6YDW-helper", 1),
		},
		{
			name:   "authority suffix",
			detail: strings.Replace(valid, "Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)", "Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW) helper", 1),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := claudeCodeDarwinSignatureHasPinnedIdentity(test.detail); got != test.want {
				t.Fatalf("claudeCodeDarwinSignatureHasPinnedIdentity() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsUnsafeDirectoryCustody(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	previousDirectoryValidator := validateClaudeCodeDarwinDirectory
	validateClaudeCodeDarwinDirectory = func(string) error { return errors.New("fixture write-capable ACL") }
	t.Cleanup(func() { validateClaudeCodeDarwinDirectory = previousDirectoryValidator })
	err := validateClaudeCodeAgentProvenance(SetupOpts{AgentExecutable: path})
	if err == nil || !strings.Contains(err.Error(), "fixture write-capable ACL") {
		t.Fatalf("unsafe directory custody error = %v, want ACL refusal", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsUnsafeFileACL(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	previousDirectoryValidator := validateClaudeCodeDarwinDirectory
	previousOwnerValidator := validateClaudeCodeDarwinOwner
	previousFileACLValidator := validateClaudeCodeDarwinFileACL
	validateClaudeCodeDarwinDirectory = func(string) error { return nil }
	validateClaudeCodeDarwinOwner = func(string, os.FileInfo) error { return nil }
	validateClaudeCodeDarwinFileACL = func(string) error { return errors.New("fixture file write-capable ACL") }
	t.Cleanup(func() {
		validateClaudeCodeDarwinDirectory = previousDirectoryValidator
		validateClaudeCodeDarwinOwner = previousOwnerValidator
		validateClaudeCodeDarwinFileACL = previousFileACLValidator
	})
	err := validateClaudeCodeAgentProvenance(SetupOpts{AgentExecutable: path})
	if err == nil || !strings.Contains(err.Error(), "fixture file write-capable ACL") {
		t.Fatalf("unsafe file ACL error = %v, want ACL refusal", err)
	}
}

func stubClaudeCodeDarwinIdentity(t *testing.T, quarantine string) {
	t.Helper()
	previousCommand := runClaudeCodeDarwinIdentityCommand
	previousQuarantine := readClaudeCodeDarwinQuarantine
	previousVersionProbe := probeClaudeCodeDarwinAgentVersion
	runClaudeCodeDarwinIdentityCommand = func(path string, args ...string) (string, error) {
		switch path {
		case "/usr/bin/codesign":
			if len(args) > 0 && args[0] == "-d" {
				return "Identifier=com.anthropic.claude-code\n" +
					"Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\n" +
					"TeamIdentifier=Q6L2SF6YDW\n", nil
			}
			return "", nil
		case "/usr/bin/lipo":
			arch := runtime.GOARCH
			if arch == "amd64" {
				arch = "x86_64"
			}
			return arch, nil
		default:
			return "", errors.New("unexpected command")
		}
	}
	readClaudeCodeDarwinQuarantine = func(string) (string, error) {
		if quarantine != "" {
			return quarantine, nil
		}
		return "", unix.ENOATTR
	}
	probeClaudeCodeDarwinAgentVersion = func(string, string, string) (string, error) {
		return "2.1.239 (Claude Code)", nil
	}
	t.Cleanup(func() {
		runClaudeCodeDarwinIdentityCommand = previousCommand
		readClaudeCodeDarwinQuarantine = previousQuarantine
		probeClaudeCodeDarwinAgentVersion = previousVersionProbe
	})
}

func writeClaudeCodeDarwinReceipt(t *testing.T, dir, path, rawVersion, digest string) {
	t.Helper()
	writeClaudeCodeDarwinReceiptAt(t, dir, path, rawVersion, digest, time.Now().UTC().Truncate(time.Second))
}

func writeClaudeCodeDarwinReceiptAt(
	t *testing.T,
	dir, path, rawVersion, digest string,
	selectedAt time.Time,
) {
	t.Helper()
	if digest == "" {
		_, digest, _ = setupSelectedAgentExecutableEvidence(path)
	}
	selectedAt = selectedAt.UTC().Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     selectedAt.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"claudecode": {
				Connector:         "claudecode",
				Source:            "setup-selected",
				Executable:        path,
				RawVersion:        rawVersion,
				NormalizedVersion: "2.1.239",
				SHA256:            digest,
				SelectedAt:        selectedAt.Format(time.RFC3339),
				ExpiresAt:         selectedAt.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenance(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	dir := filepath.Dir(path)
	version := "2.1.239 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, path, version, "")
	if err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClaudeCodeNativeImageRejectsSpoofedTextWithoutAppleAnchor(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	previous := runClaudeCodeDarwinIdentityCommand
	runClaudeCodeDarwinIdentityCommand = func(tool string, args ...string) (string, error) {
		if tool == "/usr/bin/codesign" && len(args) > 0 && args[0] == "--verify" {
			if !containsDarwinRequirementArg(args, "-R") || !containsDarwinRequirementArg(args, claudeCodeDarwinRequirement) {
				t.Fatalf("codesign verification lacks pinned requirement: %#v", args)
			}
			return "Identifier=com.anthropic.claude-code\nTeamIdentifier=Q6L2SF6YDW", errors.New("untrusted self-signed anchor")
		}
		return previous(tool, args...)
	}
	if err := validateClaudeCodeDarwinNativeImage(path); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("spoofed Claude signature error = %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsManifestVersionMismatch(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	probeClaudeCodeDarwinAgentVersion = func(string, string, string) (string, error) {
		return "2.1.238 (Claude Code)", nil
	}
	dir := filepath.Dir(path)
	version := "2.1.239 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, path, version, "")
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match protected version") {
		t.Fatalf("version mismatch error = %v, want refusal", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsQuarantine(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "0081;quarantined")
	dir := filepath.Dir(path)
	version := "2.1.239 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, path, version, "")
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	})
	if err == nil || !strings.Contains(err.Error(), "still quarantined") {
		t.Fatalf("quarantine error = %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsEmptyQuarantineAttribute(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	previousQuarantine := readClaudeCodeDarwinQuarantine
	readClaudeCodeDarwinQuarantine = func(string) (string, error) { return "", nil }
	t.Cleanup(func() { readClaudeCodeDarwinQuarantine = previousQuarantine })
	dir := filepath.Dir(path)
	version := "2.1.239 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, path, version, "")
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	})
	if err == nil || !strings.Contains(err.Error(), "still quarantined") {
		t.Fatalf("empty quarantine attribute error = %v, want quarantine refusal", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsMissingExecutableWithProtectedEvidence(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	dir := filepath.Dir(path)
	writeClaudeCodeDarwinReceipt(t, dir, path, "2.1.239 (Claude Code)", "")
	err := validateClaudeCodeAgentProvenance(SetupOpts{DataDir: dir})
	if err == nil || !strings.Contains(err.Error(), "selected executable is missing") {
		t.Fatalf("missing executable error = %v, want protected-evidence refusal", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceIgnoresCodexOnlySelectionEvidence(t *testing.T) {
	dir := t.TempDir()
	selectedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     selectedAt.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"codex": {
				Connector:         "codex",
				Source:            "setup-selected",
				Executable:        filepath.Join(dir, "codex"),
				RawVersion:        "codex 0.146.0",
				NormalizedVersion: "0.146.0",
				SHA256:            strings.Repeat("a", 64),
				SelectedAt:        selectedAt.Format(time.RFC3339),
				ExpiresAt:         selectedAt.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), body, 0o600); err != nil {
		t.Fatal(err)
	}

	// The Codex receipt is deliberately expired: stale evidence for another
	// connector must not turn an empty legacy Claude executable into a repair
	// error.
	if err := validateClaudeCodeAgentProvenance(SetupOpts{DataDir: dir}); err != nil {
		t.Fatalf("Codex-only protected selection was treated as Claude evidence: %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceFailsClosedOnAmbiguousSelectionState(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "malformed-json", body: []byte("{")},
		{
			name: "mismatched-connector-identity",
			body: []byte(`{
  "schema_version": 1,
  "updated_at": "2026-08-22T12:00:00Z",
  "selections": {
    "codex": {"connector": "claudecode"}
  }
}`),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), test.body, 0o600); err != nil {
				t.Fatal(err)
			}
			err := validateClaudeCodeAgentProvenance(SetupOpts{DataDir: dir})
			if err == nil || !strings.Contains(err.Error(), "selected executable is missing") {
				t.Fatalf("ambiguous protected state error = %v, want missing-executable refusal", err)
			}
		})
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceIgnoresCanonicalCodexOnlyHookLock(t *testing.T) {
	dir := t.TempDir()
	updatedAt := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	writeClaudeCodeDarwinHookLockFixture(t, dir, hookContractLock{
		Version:   hookContractLockVersion,
		UpdatedAt: updatedAt,
		Connectors: map[string]HookContractLockEntry{
			"codex": {Connector: "codex", UpdatedAt: updatedAt},
		},
	})
	if err := validateClaudeCodeAgentProvenance(SetupOpts{DataDir: dir}); err != nil {
		t.Fatalf("canonical Codex-only hook lock was treated as Claude evidence: %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceFailsClosedOnAmbiguousHookLock(t *testing.T) {
	updatedAt := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "malformed-json", body: []byte("{")},
		{
			name: "mismatched-connector-identity",
			body: mustMarshalClaudeCodeDarwinHookLock(t, hookContractLock{
				Version:   hookContractLockVersion,
				UpdatedAt: updatedAt,
				Connectors: map[string]HookContractLockEntry{
					"codex": {Connector: "claudecode", UpdatedAt: updatedAt},
				},
			}),
		},
		{
			name: "noncanonical-key",
			body: mustMarshalClaudeCodeDarwinHookLock(t, hookContractLock{
				Version:   hookContractLockVersion,
				UpdatedAt: updatedAt,
				Connectors: map[string]HookContractLockEntry{
					" codex ": {Connector: "codex", UpdatedAt: updatedAt},
				},
			}),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), test.body, 0o600); err != nil {
				t.Fatal(err)
			}
			err := validateClaudeCodeAgentProvenance(SetupOpts{DataDir: dir})
			if err == nil || !strings.Contains(err.Error(), "selected executable is missing") {
				t.Fatalf("ambiguous protected hook lock error = %v, want missing-executable refusal", err)
			}
		})
	}
}

func writeClaudeCodeDarwinHookLockFixture(t *testing.T, dataDir string, lock hookContractLock) {
	t.Helper()
	body := mustMarshalClaudeCodeDarwinHookLock(t, lock)
	if err := atomicWriteFile(filepath.Join(dataDir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMarshalClaudeCodeDarwinHookLock(t *testing.T, lock hookContractLock) []byte {
	t.Helper()
	body, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsReceiptDigestMismatch(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	dir := filepath.Dir(path)
	version := "2.1.239 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, path, version, strings.Repeat("a", 64))
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	})
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("digest error = %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsReceiptVersionMismatch(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	dir := filepath.Dir(path)
	writeClaudeCodeDarwinReceipt(t, dir, path, "2.1.239 (Claude Code)", "")
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: "2.1.240 (Claude Code)",
	})
	if err == nil || !strings.Contains(err.Error(), "different agent version") {
		t.Fatalf("version error = %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsReceiptPathMismatch(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	dir := filepath.Dir(path)
	version := "2.1.239 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, filepath.Join(dir, "other"), version, strings.Repeat("a", 64))
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match protected evidence") {
		t.Fatalf("path error = %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenancePrefersNewerLockOverOlderReceipt(t *testing.T) {
	dir := t.TempDir()
	lockedPath := writeClaudeCodeDarwinFixtureAt(t, dir, "claude-locked")
	stalePath := writeClaudeCodeDarwinFixtureAt(t, dir, "claude-stale")
	stubClaudeCodeDarwinIdentity(t, "")
	version := "2.1.239 (Claude Code)"
	lockedAt := time.Now().UTC().Truncate(time.Second)
	entry := NewHookContractLockEntry(
		SetupOpts{DataDir: dir, AgentExecutable: lockedPath, AgentVersion: version},
		NewClaudeCodeConnector(),
		"test",
	)
	entry.UpdatedAt = lockedAt.Format(time.RFC3339)
	lock := hookContractLock{
		Version:    hookContractLockVersion,
		UpdatedAt:  entry.UpdatedAt,
		Connectors: map[string]HookContractLockEntry{"claudecode": entry},
	}
	body, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	writeClaudeCodeDarwinReceiptAt(
		t,
		dir,
		stalePath,
		version,
		"",
		lockedAt.Add(-time.Minute),
	)

	if err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: lockedPath, AgentVersion: version,
	}); err != nil {
		t.Fatalf("newer lock should retain authority over stale receipt: %v", err)
	}
}

func TestClaudeCodeDarwinLockSealsSelectedExecutable(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	dir := filepath.Dir(path)
	version := "2.1.239 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, path, version, "")
	if got := LoadCachedAgentExecutable(dir, "claudecode"); got != path {
		t.Fatalf("receipt-backed cached Claude executable = %q, want %q", got, path)
	}
	if got := LoadCachedAgentVersion(dir, "claudecode"); got != version {
		t.Fatalf("receipt-backed cached Claude version = %q, want %q", got, version)
	}

	entry := NewHookContractLockEntry(
		SetupOpts{DataDir: dir, AgentExecutable: path, AgentVersion: version},
		NewClaudeCodeConnector(),
		"test",
	)
	if entry.AgentExecutable != path ||
		entry.AgentExecutableSource != "setup-selected" ||
		len(entry.AgentExecutableSHA256) != 64 {
		t.Fatalf("protected executable evidence = %#v", entry)
	}
	lock := hookContractLock{
		Version:    hookContractLockVersion,
		UpdatedAt:  entry.UpdatedAt,
		Connectors: map[string]HookContractLockEntry{"claudecode": entry},
	}
	body, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, agentSelectionFile)); err != nil {
		t.Fatal(err)
	}
	if got := LoadCachedAgentExecutable(dir, "claudecode"); got != path {
		t.Fatalf("lock-backed cached Claude executable = %q, want %q", got, path)
	}
	if got := LoadCachedAgentVersion(dir, "claudecode"); got != version {
		t.Fatalf("lock-backed cached Claude version = %q, want %q", got, version)
	}
}
