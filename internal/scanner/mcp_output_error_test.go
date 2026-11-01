// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-6:GAP-0366: the stdout error goes into the scan error, the audit
// row and gateway.log as one printable line: control characters (ESC, BEL,
// NUL) and format characters (a bidi override, a zero-width space) are
// dropped before the cap; whitespace folds to single spaces.
func TestMCPOutputErrorDropsControlAndFormatCharacters(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"error":    "scan failed: \x1b]0;title\x07 refusing\x00 to\tscan\r\n\u202eevil\u200b \u2066x\u2069 " + strings.Repeat("\x1b", 3000) + "end",
		"findings": []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := mcpOutputError(payload)
	for _, r := range got {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("mcpOutputError kept %U: %q", r, got)
		}
	}
	if want := "scan failed: ]0;title refusing to scan evil x end"; got != want {
		t.Fatalf("mcpOutputError = %q, want %q", got, want)
	}
}

// When stderr is empty, ScanResult.ScanError is the stdout error itself,
// with no "; " separator left at its end.
func TestMCPScanErrorOfAnEmptyStderrHasNoTrailingSeparator(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", "")
	errText := "scan failed: refusing to scan local MCP server 'x': command 'node' is not an allowlisted stdio launcher (allowed: npx, uvx)"
	payload, err := json.Marshal(map[string]any{"scanner": "mcp-scanner", "target": "x", "error": errText, "findings": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	binary := buildScannerFixture(t, string(payload)+"\n", 1)
	prior := runMCPScannerCommand
	t.Cleanup(func() { runMCPScannerCommand = prior })
	runMCPScannerCommand = func(_ context.Context, cmd *exec.Cmd) error { return cmd.Run() }
	res, err := NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: binary}, config.LLMConfig{}, config.CiscoAIDefenseConfig{}).Scan(context.Background(), "x")
	if res == nil || res.ScanError != errText {
		t.Fatalf("ScanError = %+v, want %q", res, errText)
	}
	if want := "scanner mcp-scanner exited 1 (" + errText + "; stderr=)"; err == nil || err.Error() != want {
		t.Fatalf("Scan() error %v, want %q", err, want)
	}
}
