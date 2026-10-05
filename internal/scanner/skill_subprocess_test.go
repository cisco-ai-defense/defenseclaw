// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestSkillScanner_SubprocessExitEmptyStdoutFails(t *testing.T) {
	bin := buildScannerFixture(t, "", 7)
	ss := NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: bin}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	_, err := ss.Scan(context.Background(), "/tmp/target")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exited 7") {
		t.Fatalf("subprocess exit detail missing from canonical scan failure: %v", err)
	}
}

// A custom policy whose bytes do not match policy_file.digest is a scan
// error before the scanner starts: never a scan with some other policy.
func TestSkillScanner_CustomPolicyDigestMismatchFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("policy_name: custom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ss := NewSkillScannerFromLLM(config.SkillScannerConfig{
		Binary:     filepath.Join(t.TempDir(), "not-run"),
		Policy:     config.SkillScannerPolicyCustom,
		PolicyFile: config.AssetFileRef{Path: path, Digest: "sha256:" + strings.Repeat("0", 64)},
	}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	result, err := ss.Scan(context.Background(), "/tmp/target")
	if err == nil || result == nil || !strings.Contains(result.ScanError, "digest mismatch") {
		t.Fatalf("Scan() = %+v, %v; want a digest-mismatch scan error", result, err)
	}
}
