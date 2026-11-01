// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func TestEnterpriseLifecycleArgumentsUsePublicMachineTransaction(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	opts := enterpriseSetupOptions{
		Action:                        "install",
		Config:                        `C:\staging\config.yaml`,
		Manifest:                      `C:\staging\targets.yaml`,
		AttestAgentApplicationControl: true,
		AttestClaudeEffectivePolicy:   true,
		NoStart:                       true,
		JSON:                          true,
	}
	want := []string{
		"enterprise", "windows", "install",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--broker-binary", filepath.Join(stage, "defenseclaw-cmid-broker.exe"),
		"--gateway-binary", filepath.Join(stage, "defenseclaw-gateway.exe"),
		"--hook-binary", filepath.Join(stage, "defenseclaw-hook.exe"),
		"--cli-binary", filepath.Join(stage, "defenseclaw.exe"),
		"--config", opts.Config,
		"--manifest", opts.Manifest,
		"--bootstrap-parent", filepath.Join(stage, enterpriseSetupScratchDirName),
		"--no-start", "--json",
		"--attest-agent-application-control",
		"--attest-claude-effective-policy",
	}
	if got := enterpriseLifecycleArguments(stage, opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

func TestEnterpriseLifecycleReadOnlyDoesNotSupplyReplacementArtifacts(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: "status", JSON: true})
	want := []string{
		"enterprise", "windows", "status",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--bootstrap-parent", filepath.Join(stage, enterpriseSetupScratchDirName),
		"--json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

// The outer signed DefenseClawSetup EXE always forwards its own protected
// %ProgramData%\DefenseClaw-Enterprise-Setup-<hex>\scratch directory as
// install-enterprise.ps1's -BootstrapParent, so the one-shot bootstrap
// dir does not land under C:\Windows\Temp. On Azure-AD-joined hosts,
// C:\Windows\Temp carries an inherited Allow ACE for the interactive AAD
// principal with replacement rights, which fails the module's later
// trusted-ancestor walk on rendered YAML content.
func TestEnterpriseLifecycleArgumentsAlwaysForwardsBootstrapParent(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	wantParent := filepath.Join(stage, enterpriseSetupScratchDirName)
	for _, action := range []string{"install", "upgrade", "repair", "reconcile", "status", "verify", "uninstall"} {
		t.Run(action, func(t *testing.T) {
			got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: action})
			foundIndex := -1
			for index := 0; index < len(got)-1; index++ {
				if got[index] == "--bootstrap-parent" {
					foundIndex = index
					break
				}
			}
			if foundIndex < 0 {
				t.Fatalf("%s: --bootstrap-parent missing from args: %#v", action, got)
			}
			if got[foundIndex+1] != wantParent {
				t.Fatalf("%s: --bootstrap-parent value = %q, want %q", action, got[foundIndex+1], wantParent)
			}
		})
	}
}

func TestIsEnterpriseSetupStagingChildAcceptsOnlyCapabilityDirectories(t *testing.T) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Skipf("ProgramData unavailable: %v", err)
	}
	const capability = "0123456789abcdef0123456789abcdef"
	cisco := filepath.Join(programData, "Cisco")
	for name, test := range map[string]struct {
		root, parent string
		want         bool
	}{
		"ProgramData":         {filepath.Join(programData, enterpriseSetupStagePrefix+capability), programData, true},
		"ProgramData Cisco":   {filepath.Join(cisco, enterpriseSetupStagePrefix+capability), cisco, true},
		"wrong parent":        {filepath.Join(programData, "Other", enterpriseSetupStagePrefix+capability), filepath.Join(programData, "Other"), false},
		"parent mismatch":     {filepath.Join(cisco, enterpriseSetupStagePrefix+capability), programData, false},
		"short capability":    {filepath.Join(programData, enterpriseSetupStagePrefix+"0123"), programData, false},
		"ProgramData itself":  {programData, filepath.Dir(programData), false},
		"other staging names": {filepath.Join(programData, "DefenseClaw-PowerShell-"+capability), programData, false},
	} {
		if got := isEnterpriseSetupStagingChild(test.root, test.parent); got != test.want {
			t.Fatalf("%s: isEnterpriseSetupStagingChild(%q, %q) = %t, want %t", name, test.root, test.parent, got, test.want)
		}
	}
}

func testEnterprisePayload(t *testing.T) enterprisePayload {
	t.Helper()
	files := fstest.MapFS{}
	entries := map[string]enterprisePayloadManifestFile{}
	for _, name := range requiredPayloadFiles {
		body := []byte("staged " + name)
		digest := sha256.Sum256(body)
		files["payload/"+name] = &fstest.MapFile{Data: body}
		entries[name] = enterprisePayloadManifestFile{Name: name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(body))}
	}
	return enterprisePayload{Files: entries, PayloadFS: files}
}

func TestStageEnterprisePayloadPinsFilesAndAlwaysCleansUp(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("protected ProgramData staging requires an elevated token")
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Fatalf("ProgramData: %v", err)
	}
	stage, err := stageEnterprisePayload(testEnterprisePayload(t), programData)
	if err != nil {
		t.Fatalf("stageEnterprisePayload: %v", err)
	}
	t.Cleanup(stage.cleanupAndAccept)
	if !strings.HasPrefix(filepath.Base(stage.root), enterpriseSetupStagePrefix) {
		t.Fatalf("stage root = %q", stage.root)
	}
	staged := filepath.Join(stage.root, "defenseclaw.exe")
	if err := os.WriteFile(staged, []byte("replaced"), 0o600); err == nil {
		t.Fatal("a staged payload file was rewritten while pinned")
	}
	if err := os.Rename(stage.root, stage.root+".moved"); err == nil {
		t.Fatal("the pinned staging directory was renamed")
	}
	for _, name := range requiredPayloadFiles {
		sd, err := windows.GetNamedSecurityInfo(filepath.Join(stage.root, name), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			t.Fatalf("%s: GetNamedSecurityInfo: %v", name, err)
		}
		owner, _, _ := sd.Owner()
		if owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Fatalf("%s owner = %v, want Administrators", name, owner)
		}
	}
	// Entries the lifecycle leaves behind are accepted and removed with the
	// stage rather than failing cleanup.
	if err := os.WriteFile(filepath.Join(stage.root, "unexpected.log"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(stage.root, enterpriseSetupScratchDirName, "nested"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	stage.releaseFiles()
	if err := stage.cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Lstat(stage.root); !os.IsNotExist(err) {
		t.Fatalf("stage survived cleanup: %v", err)
	}
	if err := stage.cleanup(); err != nil {
		t.Fatalf("second cleanup: %v", err)
	}
}
