// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-1:GAP-0011: the installers pipe these lines through PowerShell,
// which decodes a native command's output with the console code page, so a
// check mark came out as mojibake on Windows PowerShell 5.1. Redirected
// Windows output uses the ASCII stand-in, as the other gateway output does.
func TestConnectorLifecycleLinesUseASCIIWhenGlyphsDoNotFit(t *testing.T) {
	prev := asciiGlyphs
	asciiGlyphs = func() bool { return true }
	t.Cleanup(func() { asciiGlyphs = prev })

	dir := t.TempDir()
	defer withConnectorState(t, dir, "openclaw")()
	previousHome := connector.OpenClawHomeOverride
	connector.OpenClawHomeOverride = filepath.Join(dir, "openclaw-home")
	if err := os.MkdirAll(connector.OpenClawHomeOverride, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connector.OpenClawHomeOverride = previousHome })

	stdout, stderr, exitCode := runConnectorCmd(t, "verify", "--connector", "openclaw")
	if exitCode != 0 || !strings.Contains(stdout, "  OK openclaw: no residual DefenseClaw state detected") || strings.ContainsRune(stdout, '✓') {
		t.Fatalf("verify: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	source, err := os.ReadFile("connector_cmd.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), `Style("✓"`) || strings.Contains(string(source), `Style("✗"`) {
		t.Fatal("connector_cmd.go prints a glyph without its ASCII stand-in")
	}
}
