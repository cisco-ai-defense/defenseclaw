// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2227: the managed Windows guardian checked the shared inspect-* script
// digests but not the connector's own hook script, so a deleted or edited
// claude-code-hook.sh stayed missing until another runtime file drifted.
func TestVerifyManagedConnectorHookScriptDigestsNamesAMissingOrEditedScript(t *testing.T) {
	dataDir := t.TempDir()
	hooks := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hooks, "claude-code-hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n# DefenseClaw hook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, exists, err := stableManagedArtifactDigestForOwner(script, "test", managedHookRuntimeArtifactMaxBytes, "")
	if err != nil || !exists {
		t.Fatalf("digest fixture: exists=%v err=%v", exists, err)
	}
	opts := SetupOpts{DataDir: dataDir}
	conn := NewClaudeCodeConnector()
	entry := HookContractLockEntry{Connector: "claudecode", HookScriptDigests: map[string]string{
		"claude-code-hook.sh": digest,
		// A shared script is checked by VerifyManagedSharedHookScriptDigests,
		// and a machine binary is not in the hooks folder.
		"inspect-tool.sh":      "sha256:" + strings.Repeat("0", 64),
		"defenseclaw-hook.exe": "sha256:" + strings.Repeat("1", 64),
	}}
	if err := VerifyManagedConnectorHookScriptDigests(opts, conn, entry, ""); err != nil {
		t.Fatalf("an intact script failed: %v", err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManagedConnectorHookScriptDigests(opts, conn, entry, ""); err == nil ||
		!strings.Contains(err.Error(), "digest mismatch: "+script) {
		t.Fatalf("an edited script: err=%v, want a digest mismatch naming it", err)
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManagedConnectorHookScriptDigests(opts, conn, entry, ""); err == nil ||
		!strings.Contains(err.Error(), "is missing: "+script) {
		t.Fatalf("a deleted script: err=%v, want it named missing", err)
	}
	// A lock an earlier release wrote without the script's digest is not
	// checked.
	delete(entry.HookScriptDigests, "claude-code-hook.sh")
	if err := VerifyManagedConnectorHookScriptDigests(opts, conn, entry, ""); err != nil {
		t.Fatalf("a lock without the script digest failed: %v", err)
	}
}
