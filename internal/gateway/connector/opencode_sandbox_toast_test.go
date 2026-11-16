// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// V2 server plugins return the policy reason through the rejected tool
// Promise; they do not invoke the retired V1 TUI toast API.
func TestOpenCodeSandboxBlockPreservesTheNativeToolError(t *testing.T) {
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
	if lines[1] != "notices:[]" {
		t.Fatalf("unexpected sandbox UI callback: %q", lines[1])
	}
}
