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
// the AVC-facing assembler
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
}

// #1281: the standalone build links the payload binding of the payload it
// appends into the outer Setup, computed by the same Go code the Setup runs
// (windows-repro-manifest payload-binding), and no longer copies the
// payload into the retired //go:embed directory.
func TestStandaloneBuildLinksThePayloadBinding(t *testing.T) {
	script := readEnterpriseSetupContractFile(t, "packaging/windows/standalone/build-setup.sh")
	for _, required := range []string{
		`PAYLOAD_BINDING="$("${EMITTER}" payload-binding --payload-dir "${PAYLOAD_ONLY}" --distribution-flavor "${FLAVOR}" \
    --version "${VERSION}" --source-commit "${SOURCE_COMMIT}")"`,
		`-SourceCommit "${SOURCE_COMMIT}"`,
		`-Version "${VERSION}"`,
		`-X main.standalonePayloadBinding=${PAYLOAD_BINDING}`,
		`-PayloadDir "${PAYLOAD_ONLY}"`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("build-setup.sh is missing %q", required)
		}
	}
	if strings.Contains(script, "cmd/defenseclaw-enterprise-setup/payload") {
		t.Error("build-setup.sh still writes the retired enterprise Setup embed directory")
	}
}

func TestManagedSetupOmitsFleetCompiler(t *testing.T) {
	contains := func(files []string, name string) bool {
		for _, file := range files {
			if file == name {
				return true
			}
		}
		return false
	}
	if contains(standalonePayloadFiles, "policy_compiler.py") {
		t.Fatal("standalone Setup payload includes the Fleet policy compiler")
	}
	if contains(requiredPayloadFiles, "policy_compiler.py") {
		t.Fatal("Secure Client payload unexpectedly includes standalone Fleet compiler")
	}
	if strings.Contains(readEnterpriseSetupContractFile(t, "packaging/windows/standalone/build-setup.sh"), "policy_compiler.py") {
		t.Fatal("standalone build recipe includes the Fleet compiler")
	}
	if strings.Contains(readEnterpriseSetupContractFile(t, "cmd/windows-avc-assembler/main.go"), "policy_compiler.py") {
		t.Fatal("signed standalone assembler includes the Fleet compiler")
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

// TestSecureClientLifecycleRunsNoFleetStep pins DAMAGE-678 A2: Secure Client
// Install, Upgrade and Repair keep their 1.0.1 behaviour. The gateway alone
// refuses a Secure Client config with fleet.enabled.
func TestSecureClientLifecycleRunsNoFleetStep(t *testing.T) {
	module := readEnterpriseSetupContractFile(t, "packaging/windows/DefenseClawEnterprise.psm1")
	for _, forbidden := range []string{
		"preflight-secure-client-fleet",
		"Assert-DefenseClawSecureClientFleetSourcePreflight",
	} {
		if strings.Contains(module, forbidden) {
			t.Fatalf("Secure Client lifecycle runs a Fleet step again: %q", forbidden)
		}
	}
	entry := strings.Index(module, "function Invoke-DefenseClawEnterpriseLifecycle {")
	if entry < 0 {
		t.Fatal("enterprise lifecycle entry point is missing")
	}
	lifecycle := module[entry:]
	profile := strings.Index(lifecycle, "if (Test-DefenseClawStandaloneProfile) {")
	inspect := strings.Index(lifecycle, "$standaloneFleetEnabled = Test-DefenseClawStandaloneFleetSourceEnabled `")
	if profile < 0 || inspect < profile {
		t.Fatalf("Fleet source inspection must stay inside the standalone branch (profile %d, inspect %d)", profile, inspect)
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
	supplied := strings.Index(lifecycle, "if (-not [string]::IsNullOrWhiteSpace($PolicyCompiler)) {")
	add := strings.Index(lifecycle, "Add-DefenseClawStandaloneFleetCompilerSource `")
	kept := strings.Index(lifecycle, "elseif ([string]::IsNullOrEmpty((Get-DefenseClawRecordedStandaloneCompilerPath -Layout $layout))) {")
	refusal := strings.Index(lifecycle, "throw ('Fleet-enabled standalone Setup carries no Fleet policy compiler and this host has no recorded one to keep; turn Fleet off in the config, then ' + (Format-DefenseClawRerunStep) + ' with that config')")
	mutation := strings.Index(lifecycle, "Initialize-DefenseClawManagedRoot `")
	if deferredGuard < 0 || inspect < deferredGuard || gate < inspect || supplied < gate || add < supplied || kept < add || refusal < kept || mutation < refusal {
		t.Fatalf("Fleet-on without a recorded compiler must be refused before managed-root mutation (deferred guard %d, inspect %d, gate %d, supplied %d, add %d, kept %d, refusal %d, mutation %d)", deferredGuard, inspect, gate, supplied, add, kept, refusal, mutation)
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

// moduleFunction returns one function of the Windows enterprise module.
func moduleFunction(t *testing.T, module, name string) string {
	t.Helper()
	start := strings.Index(module, "function "+name+" {")
	if start < 0 {
		t.Fatalf("module function %s is missing", name)
	}
	body := module[start:]
	if end := strings.Index(body[1:], "\nfunction "); end >= 0 {
		body = body[:end+1]
	}
	return body
}

// TestStandaloneFleetUpgradeKeepsTheRecordedCompiler pins GAP-0274: Setup
// carries no Fleet compiler, so a Fleet-on 1.0.2 host keeps the compiler it
// installed. Its layout path stays, the lifecycle records the same hash, a
// rollback restores it, and the install-tree walk accepts it only through the
// hash-checked helper. No lifecycle creates the compiler tree (GAP-0270).
func TestStandaloneFleetUpgradeKeepsTheRecordedCompiler(t *testing.T) {
	module := readEnterpriseSetupContractFile(t, "packaging/windows/DefenseClawEnterprise.psm1")
	for _, check := range []struct{ function, want string }{
		{"Get-DefenseClawLayout", "$layout['CompilerPath'] = [IO.Path]::Combine($layout.InstallRoot, 'lib', 'defenseclaw', 'policy_compiler.py')"},
		{"Get-DefenseClawArtifactPath", "'compiler' { Get-DefenseClawOptionalLayoutValue -Layout $Layout -Name CompilerPath }"},
		{"New-DefenseClawDeploymentMetadata", "@('compiler', (Get-DefenseClawOptionalLayoutValue -Layout $Layout -Name CompilerPath)),"},
		{"New-DefenseClawTransaction", "(Get-DefenseClawOptionalLayoutValue -Layout $Layout -Name CompilerPath),"},
		{"Set-DefenseClawManagedAcls", "Set-DefenseClawPathAcl -Path $compilerPath -Kind ServiceInstallFile -GatewayServiceSID $gatewaySID"},
		{"Assert-DefenseClawEnterpriseDeployment", "-Path $compilerPath `"},
		{"Assert-DefenseClawManagedInstallTree", "$recordedCompiler = Get-DefenseClawRecordedStandaloneCompilerPath -Layout $Layout"},
		{"Get-DefenseClawRecordedStandaloneCompilerPath", "if (-not [string]::Equals($actual, $recorded, [StringComparison]::OrdinalIgnoreCase)) {"},
		{"Get-DefenseClawRecordedStandaloneCompilerPath", "if (-not (Test-DefenseClawStandaloneProfile)) {"},
	} {
		if !strings.Contains(moduleFunction(t, module, check.function), check.want) {
			t.Errorf("%s omits %q", check.function, check.want)
		}
	}
	if strings.Contains(moduleFunction(t, module, "New-DefenseClawLayoutDirectories"), "Compiler") {
		t.Error("a lifecycle creates the retired compiler tree again")
	}
	helper := moduleFunction(t, module, "Get-DefenseClawRecordedStandaloneCompilerPath")
	for _, forbidden := range []string{"Copy-Item", "Install-DefenseClawFileAtomic", "[IO.File]::Delete", "Remove-Item"} {
		if strings.Contains(helper, forbidden) {
			t.Errorf("the recorded-compiler check changes the compiler: %q", forbidden)
		}
	}
}

func TestEnterpriseWorkflowValidatesPublicContractsWithoutPrivateRepositoryAccess(t *testing.T) {
	// The same public checks run for pull requests to main (the
	// enterprise-setup-contracts job in ci.yml, gated by the Enterprise
	// Required aggregate) and to the AVC machine-installer branch.
	// A Windows checkout can have CRLF line endings.
	ci := strings.ReplaceAll(readEnterpriseSetupContractFile(t, ".github/workflows/ci.yml"), "\r\n", "\n")
	start := strings.Index(ci, "\n  enterprise-setup-contracts:\n")
	if start < 0 {
		t.Fatal("ci.yml has no enterprise-setup-contracts job")
	}
	end := strings.Index(ci[start+1:], "\n  enterprise-required:\n")
	if end < 0 {
		t.Fatal("ci.yml enterprise-setup-contracts job is not followed by enterprise-required")
	}
	workflows := map[string]string{
		"ci.yml enterprise-setup-contracts": ci[start : start+1+end],
		"windows-enterprise-setup.yml":      readEnterpriseSetupContractFile(t, ".github/workflows/windows-enterprise-setup.yml"),
	}
	for name, workflow := range workflows {
		for _, required := range []string{
			"packaging/scripts/lib/assemble.ps1",
			"DefenseClawSetup-Enterprise-x64.exe",
			"Validate public enterprise Setup contracts",
			"persist-credentials: false",
			"go test -count=1",
			"go vet",
			"GOOS: windows",
			"GOARCH: amd64",
			"go build -trimpath",
			"[Management.Automation.Language.Parser]::ParseFile",
			"bash -n packaging/scripts/build-managed-windows-bundle.sh",
			"go build -tags ga ./internal/ipc/...",
			// The refusal must come from the gate, not an unrelated build error.
			`authposture_gagate\.go:.*authpostureGAApproved`,
		} {
			if !strings.Contains(workflow, required) {
				t.Errorf("%s is missing %q", name, required)
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
				t.Errorf("%s must not contain %q", name, forbidden)
			}
		}
	}
	if !strings.Contains(ci, "      - enterprise-setup-contracts\n") {
		t.Error("Enterprise Required does not need enterprise-setup-contracts")
	}
	branch := workflows["windows-enterprise-setup.yml"]
	for _, required := range []string{"pull_request:", "github.event.pull_request.head.sha || github.sha"} {
		if !strings.Contains(branch, required) {
			t.Errorf("windows-enterprise-setup.yml is missing %q", required)
		}
	}
}
