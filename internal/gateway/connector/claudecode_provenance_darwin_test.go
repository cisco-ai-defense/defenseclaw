//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

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
)

func writeClaudeCodeDarwinFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	previousTrustedParentStop := claudeCodeDarwinTrustedParentStop
	claudeCodeDarwinTrustedParentStop = root
	t.Cleanup(func() { claudeCodeDarwinTrustedParentStop = previousTrustedParentStop })
	path := filepath.Join(root, "2.1.217")
	if err := os.WriteFile(path, append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte("claude")...), 0o500); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func stubClaudeCodeDarwinIdentity(t *testing.T, quarantine string) {
	t.Helper()
	previous := runClaudeCodeDarwinIdentityCommand
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
		case "/usr/bin/xattr":
			if quarantine != "" {
				return quarantine, nil
			}
			return "", errClaudeCodeDarwinXattrMissing
		default:
			return "", errors.New("unexpected command")
		}
	}
	t.Cleanup(func() { runClaudeCodeDarwinIdentityCommand = previous })
}

func writeClaudeCodeDarwinReceipt(t *testing.T, dir, path, rawVersion, digest string) {
	t.Helper()
	if digest == "" {
		_, digest, _ = setupSelectedAgentExecutableEvidence(path)
	}
	now := time.Now().UTC().Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"claudecode": {
				Connector:         "claudecode",
				Source:            "setup-selected",
				Executable:        path,
				RawVersion:        rawVersion,
				NormalizedVersion: "2.1.217",
				SHA256:            digest,
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
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
	version := "2.1.217 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, path, version, "")
	if err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsQuarantine(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "0081;quarantined")
	dir := filepath.Dir(path)
	version := "2.1.217 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, path, version, "")
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	})
	if err == nil || !strings.Contains(err.Error(), "still quarantined") {
		t.Fatalf("quarantine error = %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsReceiptDigestMismatch(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	dir := filepath.Dir(path)
	version := "2.1.217 (Claude Code)"
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
	writeClaudeCodeDarwinReceipt(t, dir, path, "2.1.217 (Claude Code)", "")
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: "2.1.218 (Claude Code)",
	})
	if err == nil || !strings.Contains(err.Error(), "different agent version") {
		t.Fatalf("version error = %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsReceiptPathMismatch(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	stubClaudeCodeDarwinIdentity(t, "")
	dir := filepath.Dir(path)
	version := "2.1.217 (Claude Code)"
	writeClaudeCodeDarwinReceipt(t, dir, filepath.Join(dir, "other"), version, strings.Repeat("a", 64))
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: dir, AgentExecutable: path, AgentVersion: version,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match protected evidence") {
		t.Fatalf("path error = %v", err)
	}
}

func TestValidateClaudeCodeDarwinAgentProvenanceRejectsDirectoryAddedVersions(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	err := validateClaudeCodeAgentProvenance(SetupOpts{
		DataDir: filepath.Dir(path), AgentExecutable: path, AgentVersion: "2.1.219 (Claude Code)",
	})
	if err == nil || !strings.Contains(err.Error(), "DirectoryAdded") {
		t.Fatalf("uncertified-version error = %v", err)
	}
}

func TestClaudeCodeDarwinLockSealsSelectedExecutable(t *testing.T) {
	path := writeClaudeCodeDarwinFixture(t)
	entry := NewHookContractLockEntry(
		SetupOpts{AgentExecutable: path, AgentVersion: "2.1.217 (Claude Code)"},
		NewClaudeCodeConnector(),
		"test",
	)
	if entry.AgentExecutable != path ||
		entry.AgentExecutableSource != "setup-selected" ||
		len(entry.AgentExecutableSHA256) != 64 {
		t.Fatalf("protected executable evidence = %#v", entry)
	}
}
