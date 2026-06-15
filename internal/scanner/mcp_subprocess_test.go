// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A non-zero scanner exit must fail closed even when stdout parsed
// cleanly: callers branch on the returned error, so a scanner that
// exits non-zero with a well-formed `{"findings":[]}` must not be
// mistaken for a clean scan. The result is still returned so callers
// can inspect ExitCode / findings for diagnostics.
func TestMCPScanner_NonZeroExitFailsClosed(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-mcp.sh")
	script := "#!/bin/sh\n" +
		`echo '{"scanner":"mcp-scanner","target":"my-server","findings":[{"id":"f1","severity":"HIGH","title":"t","line_number":4}]}'` + "\n" +
		"exit 3\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	ms := NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: bin}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})

	// Bare server name (not a URL) so the SSRF guard is skipped and we
	// exercise the subprocess-exit path specifically.
	result, err := ms.Scan(context.Background(), "my-server")
	if err == nil {
		t.Fatal("expected non-nil error for non-zero scanner exit (fail closed)")
	}
	if result == nil {
		t.Fatal("expected result to be preserved alongside the error")
	}
	if result.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", result.ExitCode)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 parsed finding preserved for diagnostics, got %d", len(result.Findings))
	}
	if result.Findings[0].LineNumber == nil || *result.Findings[0].LineNumber != 4 {
		t.Errorf("LineNumber = %v, want 4 (line_number must deserialize)", result.Findings[0].LineNumber)
	}
}
