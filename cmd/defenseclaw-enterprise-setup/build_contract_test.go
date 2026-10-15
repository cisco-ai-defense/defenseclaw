// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func enterpriseSetupRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve enterprise Setup test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func readEnterpriseSetupContractFile(t *testing.T, relative string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(enterpriseSetupRepositoryRoot(t), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestEnterpriseAssemblerProducesOnlyTheMachineWideBootstrap asserts
// the AVC-facing assembler (docs/specs/002-windows-avc-packaging/)
// keys off the exact machine-wide bootstrap contract: same output
// filename, same source package, same payload set, no relabeling of
// the per-user Setup as managed-enterprise. Replaces the retired
// TestEnterpriseBuilderProducesOnlyTheMachineWideBootstrap that read
// scripts/build-windows-enterprise-installer.ps1 (deleted in the same
// PR that landed this test — the old builder's contract has moved
// into packaging/scripts/lib/assemble.{sh,ps1}).
func TestEnterpriseAssemblerProducesOnlyTheMachineWideBootstrap(t *testing.T) {
	assembler := readEnterpriseSetupContractFile(t, "packaging/scripts/lib/assemble.sh")
	for _, required := range []string{
		"DefenseClawSetup-Enterprise-x64.exe",
		"./cmd/defenseclaw-enterprise-setup",
		"defenseclaw-acp.exe",
		"defenseclaw-cmid-broker.exe",
		"defenseclaw-gateway.exe",
		"defenseclaw-hook.exe",
		"defenseclaw-sensor-helper.exe",
		"install-enterprise.ps1",
		"DefenseClawEnterprise.psm1",
	} {
		if !strings.Contains(assembler, required) {
			t.Errorf("assembler is missing %q", required)
		}
	}
	// The AVC-driven flow does not touch the per-user Setup — that
	// path stays under scripts/build-windows-installer.ps1 with its
	// own ValidateSet('oss') gate. Assert the assembler cannot
	// accidentally target it.
	if strings.Contains(assembler, "./cmd/defenseclaw-setup") {
		t.Fatal("assembler must not target the per-user Setup command")
	}
}

func TestStandaloneSetupCarriesFleetCompilerOnlyInStandalonePayload(t *testing.T) {
	contains := func(files []string, name string) bool {
		for _, file := range files {
			if file == name {
				return true
			}
		}
		return false
	}
	if !contains(standalonePayloadFiles, "policy_compiler.py") {
		t.Fatal("standalone Setup payload omits the Fleet policy compiler")
	}
	if contains(requiredPayloadFiles, "policy_compiler.py") {
		t.Fatal("Secure Client payload unexpectedly includes standalone Fleet compiler")
	}
	for _, path := range []string{
		"packaging/windows/standalone/build-setup.sh",
		"cmd/windows-avc-assembler/main.go",
	} {
		if !strings.Contains(readEnterpriseSetupContractFile(t, path), "policy_compiler.py") {
			t.Errorf("%s does not carry the standalone compiler", path)
		}
	}
	compiler, err := os.ReadFile(filepath.Join(enterpriseSetupRepositoryRoot(t), "edge-connector", "tools", "policy_compiler.py"))
	if err != nil {
		t.Fatal(err)
	}
	// Git for Windows otherwise checks out this text file with CRLF, changing
	// the source digest after the signed module's LF digest has been pinned.
	attributes := readEnterpriseSetupContractFile(t, ".gitattributes")
	attributes = strings.ReplaceAll(attributes, "\r\n", "\n")
	if !strings.Contains("\n"+attributes, "\nedge-connector/tools/policy_compiler.py text eol=lf\n") {
		t.Fatal("Fleet compiler checkout must preserve LF bytes on Windows")
	}
	if bytes.Contains(compiler, []byte("\r\n")) {
		t.Fatal("Fleet compiler source was checked out with CRLF bytes")
	}
	module := readEnterpriseSetupContractFile(t, "packaging/windows/DefenseClawEnterprise.psm1")
	wantPin := fmt.Sprintf("$script:DefenseClawPolicyCompilerSHA256 = '%x'", sha256.Sum256(compiler))
	if !strings.Contains(module, wantPin) {
		t.Fatal("signed Windows enterprise module does not pin the shipped Fleet compiler source")
	}
}

func TestSecureClientFleetSourcePreflightRunsBeforeLifecycleMutation(t *testing.T) {
	module := readEnterpriseSetupContractFile(t, "packaging/windows/DefenseClawEnterprise.psm1")
	entry := strings.Index(module, "function Invoke-DefenseClawEnterpriseLifecycle {")
	if entry < 0 {
		t.Fatal("enterprise lifecycle entry point is missing")
	}
	lifecycle := module[entry:]
	for _, required := range []string{
		"Assert-DefenseClawSourceDescriptorCurrent -Source $configSource",
		"Assert-DefenseClawSourceDescriptorCurrent -Source $gatewaySource",
		"'preflight-secure-client-fleet'",
	} {
		if !strings.Contains(module, required) {
			t.Fatalf("Secure Client Fleet source preflight omits %q", required)
		}
	}
	current := strings.Index(lifecycle, "Assert-DefenseClawLifecycleSourcesCurrent -Sources $sources")
	newGatewayGuard := -1
	if current >= 0 {
		if offset := strings.Index(lifecycle[current:], "$sources.ContainsKey('gateway')) {"); offset >= 0 {
			newGatewayGuard = current + offset
		}
	}
	preflight := strings.Index(lifecycle, "Assert-DefenseClawSecureClientFleetSourcePreflight `")
	mutation := strings.Index(lifecycle, "Initialize-DefenseClawManagedRoot `")
	if current < 0 || newGatewayGuard < current || preflight < newGatewayGuard || mutation < preflight {
		t.Fatalf("Secure Client Fleet source preflight must use the new gateway after authentication and before managed-root mutation (source %d, gateway guard %d, preflight %d, mutation %d)", current, newGatewayGuard, preflight, mutation)
	}
}

func TestStandaloneFleetCompilerSourceIsOptInBeforeMutation(t *testing.T) {
	module := readEnterpriseSetupContractFile(t, "packaging/windows/DefenseClawEnterprise.psm1")
	if strings.Contains(module, "@('compiler', $PolicyCompiler, 'Fleet policy compiler'") {
		t.Fatal("unconditional compiler source authentication can fail Fleet-off Setup")
	}
	entry := strings.Index(module, "function Invoke-DefenseClawEnterpriseLifecycle {")
	if entry < 0 {
		t.Fatal("enterprise lifecycle entry point is missing")
	}
	lifecycle := module[entry:]
	deferredGuard := strings.Index(lifecycle, "if (-not $DeferredConfig) {")
	inspect := strings.Index(lifecycle, "$standaloneFleetEnabled = Test-DefenseClawStandaloneFleetSourceEnabled `")
	gate := strings.Index(lifecycle, "if ($standaloneFleetEnabled) {")
	missing := strings.Index(lifecycle, "if ([string]::IsNullOrWhiteSpace($PolicyCompiler)) {")
	refusal := strings.Index(lifecycle, "throw 'Fleet-enabled standalone Setup requires -PolicyCompiler from its signed payload'")
	add := strings.Index(lifecycle, "Add-DefenseClawStandaloneFleetCompilerSource `")
	mutation := strings.Index(lifecycle, "Initialize-DefenseClawManagedRoot `")
	if deferredGuard < 0 || inspect < deferredGuard || gate < inspect || missing < gate || refusal < missing || add < refusal || mutation < add {
		t.Fatalf("Fleet-on missing compiler must be refused before managed-root mutation (deferred guard %d, inspect %d, gate %d, missing %d, refusal %d, add %d, mutation %d)", deferredGuard, inspect, gate, missing, refusal, add, mutation)
	}
	for _, required := range []string{
		"'inspect-standalone-fleet'",
		"$script:DefenseClawPolicyCompilerSHA256",
		"if ($StandaloneFleetStateKnown -and -not $StandaloneFleetEnabled)",
		"Assert-DefenseClawNoReparsePath -Path $compilerPath -AllowMissingLeaf",
	} {
		if !strings.Contains(module, required) {
			t.Fatalf("standalone Fleet opt-in lifecycle omits %q", required)
		}
	}
}

func TestOrdinarySetupBuilderCannotBeRelabeledAsEnterprise(t *testing.T) {
	builder := readEnterpriseSetupContractFile(t, "scripts/build-windows-installer.ps1")
	if !strings.Contains(builder, "[ValidateSet('oss')]") {
		t.Fatal("ordinary Setup builder is not restricted to the oss distribution flavor")
	}
	if strings.Contains(builder, "[ValidateSet('oss', 'managed-enterprise')]") {
		t.Fatal("ordinary Setup builder still accepts the managed-enterprise label")
	}
}

func TestEnterpriseWorkflowValidatesPublicContractsWithoutPrivateRepositoryAccess(t *testing.T) {
	workflow := readEnterpriseSetupContractFile(t, ".github/workflows/windows-enterprise-setup.yml")
	for _, required := range []string{
		"packaging/scripts/lib/assemble.ps1",
		"DefenseClawSetup-Enterprise-x64.exe",
		"Validate public enterprise Setup contracts",
		"pull_request:",
		"github.event.pull_request.head.sha || github.sha",
		"persist-credentials: false",
		"go test -count=1",
		"go vet",
		"GOOS: windows",
		"GOARCH: amd64",
		"go build -trimpath",
		"[Management.Automation.Language.Parser]::ParseFile",
		"bash -n packaging/scripts/build-managed-windows-bundle.sh",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("enterprise workflow is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"AI_COMMON_READ_TOKEN",
		"secrets.",
		"cisco-aispg/ai-common",
		"environment:",
		"actions/upload-artifact",
		"needs.managed-gateway",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("public enterprise workflow must not contain %q", forbidden)
		}
	}
}
