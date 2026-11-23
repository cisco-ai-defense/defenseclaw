//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rel-1-0-10:GAP-1749: Setup /install without CONFIG= and MANIFEST= stages a
// deferred deployment from installer-rendered placeholders. The placeholder
// targets.yaml must load as an explicit empty target set: a bare `targets:`
// decodes as null, the guardian refuses it as a withdrawal of enrolled hooks,
// and the staged install ended 1603. The test evaluates the exact expression
// install-enterprise.ps1 writes to $deferredManifestPath, for both profiles.
func TestDeferredConfigPlaceholderManifestIsExplicitEmptyTargetSet(t *testing.T) {
	installer, err := filepath.Abs(filepath.Join("..", "..", "packaging", "windows", "install-enterprise.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	scriptPath := filepath.Join(t.TempDir(), "gap1749-deferred-manifest.ps1")
	script := `
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:DC_GAP1749_INSTALLER, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) { throw "installer parse error: $($parseErrors[0])" }
$writes = @($ast.FindAll({
    param($n)
    $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
    $n.Member.Extent.Text -ceq 'WriteAllText' -and
    $n.Arguments.Count -ge 2 -and
    $n.Arguments[0].Extent.Text -ceq '$deferredManifestPath'
}, $true))
if ($writes.Count -ne 1) { throw "found $($writes.Count) deferred placeholder manifest writes, want 1" }
foreach ($fn in $ast.FindAll({
    param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
$deferredConnectors = @('codex')
foreach ($EnterpriseProfile in @('Standalone', 'SecureClient')) {
    $body = . ([scriptblock]::Create($writes[0].Arguments[1].Extent.Text))
    [IO.File]::WriteAllText(
        [IO.Path]::Combine($env:DC_GAP1749_OUT, "$EnterpriseProfile.yaml"),
        [string]$body,
        [Text.UTF8Encoding]::new($false)
    )
}
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "powershell.exe",
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	command.Env = append(os.Environ(), "DC_GAP1749_INSTALLER="+installer, "DC_GAP1749_OUT="+out)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("evaluate the deferred placeholder manifest: %v (ctx %v)\n%s", err, ctx.Err(), output)
	}
	for _, profile := range []string{"Standalone", "SecureClient"} {
		manifest, err := LoadManifest(filepath.Join(out, profile+".yaml"))
		if err != nil {
			t.Fatalf("%s deferred placeholder manifest refused (Setup /install without CONFIG= ends 1603): %v", profile, err)
		}
		if len(manifest.Targets) != 0 || len(manifest.Skipped) != 0 {
			t.Fatalf("%s deferred placeholder manifest = %+v, want an empty target set", profile, manifest)
		}
	}

	// The refusal that protects enrolled hooks still holds for a bare key.
	bare := filepath.Join(out, "bare.yaml")
	if err := os.WriteFile(bare, []byte("version: 1\ntargets:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(bare); err == nil || !strings.Contains(err.Error(), "refusing to withdraw enrolled hooks") {
		t.Fatalf("bare targets key = %v, want the enrolled-hook withdrawal refusal", err)
	}
}
