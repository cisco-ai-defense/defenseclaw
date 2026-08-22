// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestTrimWindowsJSONBOMAcceptsLegacyPowerShell51Output(t *testing.T) {
	plain := []byte(`{"schema_version":1}`)
	legacy := append([]byte{0xef, 0xbb, 0xbf}, plain...)
	if got := trimWindowsJSONBOM(legacy); !bytes.Equal(got, plain) {
		t.Fatalf("trim legacy BOM = %x, want %x", got, plain)
	}
	if got := trimWindowsJSONBOM(plain); !bytes.Equal(got, plain) {
		t.Fatalf("BOM-less JSON changed: %x", got)
	}
}

func TestResolveWindowsCodexManifestApplicabilityUsesGuardianManifest(t *testing.T) {
	stateRoot := filepath.Clean(`C:\ProgramData\DefenseClaw\state`)
	want := filepath.Join(stateRoot, "hook-guardian", "targets.yaml")
	oldTrust := windowsCodexRequirementsManifestTrust
	oldLoader := windowsCodexRequirementsManifestLoader
	t.Cleanup(func() {
		windowsCodexRequirementsManifestTrust = oldTrust
		windowsCodexRequirementsManifestLoader = oldLoader
	})
	var trustedPath, loadedPath string
	windowsCodexRequirementsManifestTrust = func(path, _ string) error {
		trustedPath = path
		return nil
	}
	windowsCodexRequirementsManifestLoader = func(path string) (enterprisehooks.Manifest, error) {
		loadedPath = path
		return enterprisehooks.Manifest{
			Version: 1,
			Targets: []enterprisehooks.ManifestTarget{
				{Connector: "claudecode"},
				{Connector: "codex"},
			},
		}, nil
	}

	anyEnabled, codexEnabled, claudeEnabled, err :=
		resolveWindowsCodexManifestApplicability(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if trustedPath != want || loadedPath != want {
		t.Fatalf("manifest trust/load paths = %q / %q, want exact %q", trustedPath, loadedPath, want)
	}
	if trustedPath == filepath.Join(stateRoot, "etc", "targets.yaml") {
		t.Fatal("legacy etc targets path must never be consulted")
	}
	if !anyEnabled || !codexEnabled || !claudeEnabled {
		t.Fatalf(
			"applicability any=%t codex=%t claude=%t, want all true",
			anyEnabled,
			codexEnabled,
			claudeEnabled,
		)
	}
}
