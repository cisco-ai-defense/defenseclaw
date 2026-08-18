// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const codexSetupFixtureVersion = "codex 0.144.3"

// stageCodexExecutableEvidenceFixture copies the current native Go test image
// to the product name accepted by Codex policy inspection and binds its exact
// path and digest into a realistic setup-selected contract entry. Stub-based
// gateway tests can consume the entry without launching it; Windows lifecycle
// tests pair it with the bounded app-server helper in the platform test file.
func stageCodexExecutableEvidenceFixture(
	t *testing.T,
	dataDir string,
) connector.HookContractLockEntry {
	t.Helper()

	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve gateway test executable: %v", err)
	}
	productName := "codex"
	if runtime.GOOS == "windows" {
		productName += ".exe"
	}
	targetPath := filepath.Join(dataDir, productName)
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open gateway test executable: %v", err)
	}
	defer source.Close() //nolint:errcheck

	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatalf("create Codex fixture executable: %v", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(target, hasher), source); err != nil {
		_ = target.Close()
		t.Fatalf("copy Codex fixture executable: %v", err)
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		t.Fatalf("sync Codex fixture executable: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("close Codex fixture executable: %v", err)
	}
	if err := os.Chmod(targetPath, 0o700); err != nil {
		t.Fatalf("make Codex fixture executable: %v", err)
	}

	resolution := connector.ResolveHookContract("codex", codexSetupFixtureVersion)
	if resolution.Status != connector.HookCompatibilityKnown {
		t.Fatalf("Codex fixture version did not resolve to a known contract: %+v", resolution)
	}
	entry := connector.HookContractLockEntry{
		Connector:              "codex",
		RawAgentVersion:        resolution.RawVersion,
		NormalizedAgentVersion: resolution.NormalizedVersion,
		AgentExecutable:        targetPath,
		AgentExecutableSource:  "setup-selected",
		AgentExecutableSHA256:  hex.EncodeToString(hasher.Sum(nil)),
		ContractID:             resolution.Contract.ContractID,
		CompatibilityStatus:    resolution.Status,
		CompatibilityReason:    resolution.Reason,
		UpdatedAt:              time.Now().UTC().Format(time.RFC3339),
	}
	stageCodexDiscoveryAuthorityFixture(t, dataDir, entry)
	return entry
}
