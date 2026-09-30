// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Cert opencode:OC-4: OpenCode's TUI draws a tool call the sandbox plugin
// refused as its bare command line, in the error color, and shows the
// reason only once that line is clicked, so the toast that shows the
// reason at once also says where it stays. The model still gets the bare
// reason as the tool's error.
func TestOpenCodeSandboxBlockToastSaysWhereTheReasonStays(t *testing.T) {
	server := openCodeStubGateway(t, openCodeGatewayBlock)
	t.Setenv(SandboxTokenEnv, "openshell:resolve:env:v3_DEFENSECLAW_SANDBOX_TOKEN")
	data := templateData{
		APIAddr:                  strings.TrimPrefix(server.URL, "http://"),
		FailMode:                 "closed",
		Managed:                  true,
		ConnectorName:            "opencode",
		Sandbox:                  true,
		SandboxConnectTimeout:    sandboxHookConnectTimeoutSeconds,
		SandboxMaxTime:           sandboxHookMaxTimeSeconds,
		SandboxRetryMaxTime:      sandboxHookRetryMaxTimeSeconds,
		SandboxSessionEndMaxTime: sandboxHookSessionEndMaxTimeSeconds,
	}
	path := filepath.Join(testenv.PrivateTempDir(t), "defenseclaw.mjs")
	if err := os.WriteFile(path, []byte(renderPluginAssetForTest(t, "opencode-plugin.js", data)), 0o600); err != nil {
		t.Fatal(err)
	}
	lines := runNodeHarness(t, openCodePluginHarness, path, strconv.Itoa(1))
	if len(lines) != 2 || lines[0] != "block:matched: TEST-MARKER" {
		t.Fatalf("harness output = %q, want the bare reason as the tool's error", lines)
	}
	var toasts []struct {
		Title   string `json:"title"`
		Message string `json:"message"`
		Variant string `json:"variant"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "toasts:")), &toasts); err != nil {
		t.Fatalf("toasts %q: %v", lines[1], err)
	}
	want := "matched: TEST-MARKER\n\nClick the tool's red line in the conversation to show this again."
	if len(toasts) != 1 || toasts[0].Variant != "error" || toasts[0].Title != "DefenseClaw blocked this tool call" || toasts[0].Message != want {
		t.Fatalf("toasts = %+v, want one error toast with %q", toasts, want)
	}
}
