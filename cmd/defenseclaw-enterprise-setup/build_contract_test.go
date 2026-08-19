// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
		"defenseclaw-gateway.exe",
		"defenseclaw-hook.exe",
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
