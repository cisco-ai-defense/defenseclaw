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

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-6:GAP-0258 (sweep 9, per-user macOS): `defenseclaw mcp scan --json`
// prints its refusal of a node launcher as the "error" of the JSON on stdout
// and exits 1 with nothing on stderr. The scan error read only stderr,
// "scanner mcp-scanner exited 1 (stderr=)", so the watcher retried the
// refusal with backoff instead of keeping it final, and the agent never got
// the launcher reason. The stdout error is now in the scan error; a scan
// that did not finish stays a failure that is not a launcher refusal.
func TestMCPScanJSONErrorOnStdoutCarriesTheLauncherRefusal(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", "")
	node := "scan failed: refusing to scan local MCP server 'vs9time': command 'node' is not an allowlisted stdio launcher (allowed: npx, uvx): " +
		"a scan starts only npm or PyPI packages through npx or uvx, never another program. Start the server with npx or uvx, serve it over HTTP " +
		"and use its URL, or review it and allow that definition with 'defenseclaw mcp allow <name> --command ... --args ...'"
	fixture := func(errText string) string {
		payload, err := json.Marshal(map[string]any{"scanner": "mcp-scanner", "target": "vs9time", "error": errText, "findings": []any{}})
		if err != nil {
			t.Fatal(err)
		}
		return buildScannerFixture(t, string(payload)+"\n", 1)
	}
	prior := runMCPScannerCommand
	t.Cleanup(func() { runMCPScannerCommand = prior })
	runMCPScannerCommand = func(_ context.Context, cmd *exec.Cmd) error { return cmd.Run() }
	scan := func(binary string) (*ScanResult, error) {
		return NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: binary}, config.LLMConfig{}, config.CiscoAIDefenseConfig{}).Scan(context.Background(), "vs9time")
	}

	refusal, timeout := fixture(node), fixture("scan failed: timed out waiting for the server")
	res, err := scan(refusal)
	if err == nil || !strings.Contains(err.Error(), node) || !MCPLauncherRefusal(err.Error()) || !MCPScanRefused(err) {
		t.Fatalf("Scan() error %v, want the stdout refusal, final as a launcher refusal", err)
	}
	if res == nil || !strings.Contains(res.ScanError, "command 'node' is not an allowlisted stdio launcher") {
		t.Fatalf("ScanError = %+v, want the stdout refusal when stderr is empty", res)
	}
	if _, err := scan(timeout); err == nil || !strings.Contains(err.Error(), "timed out waiting for the server") || MCPLauncherRefusal(err.Error()) {
		t.Fatalf("timeout: %v, want the stdout error, not a launcher refusal", err)
	}

	// Secure Client keeps the error of main (issue #1092).
	KeepFullFailureText(true)
	t.Cleanup(func() { KeepFullFailureText(false) })
	if _, err := scan(refusal); err == nil || err.Error() != "scanner mcp-scanner exited 1 (stderr=)" {
		t.Fatalf("Secure Client error %v, want main's", err)
	}
}

// The stdout error is one line and bounded; output without one adds nothing.
func TestMCPOutputErrorIsOneBoundedLine(t *testing.T) {
	long := `{"error":"scan failed: a\nb ` + strings.Repeat("x", 2*maxMCPOutputErrorBytes) + `","findings":[]}`
	if got := mcpOutputError([]byte(long)); strings.ContainsAny(got, "\r\n") || len(got) > maxMCPOutputErrorBytes+3 || !strings.HasPrefix(got, "scan failed: a b x") {
		t.Fatalf("mcpOutputError(long) = %d bytes %q", len(got), got[:min(len(got), 40)])
	}
	for _, out := range []string{"", `{"findings":[]}`, "not json"} {
		if got := mcpOutputError([]byte(out)); got != "" {
			t.Errorf("mcpOutputError(%q) = %q, want empty", out, got)
		}
	}
}
