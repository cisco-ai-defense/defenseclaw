// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

func applySetupPublicationACL(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
		user.User.Sid,
	))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("extract Setup publication DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		user.User.Sid,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareStagedInstallerRootProtectsMetadataAcrossFreshAndRepairPublication(
	t *testing.T,
) {
	for _, publication := range []string{"fresh-install", "repair"} {
		t.Run(publication, func(t *testing.T) {
			parent := t.TempDir()
			applySetupPublicationACL(t, parent)
			staging := filepath.Join(parent, "DefenseClaw.staging."+strings.Repeat("a", 32))
			if err := os.Mkdir(staging, 0o755); err != nil {
				t.Fatal(err)
			}
			installerRoot, err := prepareStagedInstallerRoot(staging)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{
				"upgrade-manifest.json",
				"payload-manifest.json",
				"install-state.json",
			} {
				if err := os.WriteFile(
					filepath.Join(installerRoot, name),
					[]byte("{}\n"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			}
			installRoot := filepath.Join(parent, "DefenseClaw")
			if publication == "repair" {
				if err := os.Mkdir(installRoot, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(
					installRoot,
					filepath.Join(parent, "DefenseClaw.backup."+strings.Repeat("b", 32)),
				); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(staging, installRoot); err != nil {
				t.Fatal(err)
			}
			publishedInstaller := filepath.Join(installRoot, "installer")
			if err := safefile.ValidatePrivateDirectory(publishedInstaller); err != nil {
				t.Fatalf("published installer directory custody: %v", err)
			}
			for _, name := range []string{
				"upgrade-manifest.json",
				"payload-manifest.json",
				"install-state.json",
			} {
				if err := safefile.ValidatePrivateFile(
					filepath.Join(publishedInstaller, name),
				); err != nil {
					t.Fatalf("published %s custody: %v", name, err)
				}
			}
		})
	}
}

func TestPublishMaintenanceCopyProtectsInheritedSetupCache(t *testing.T) {
	parent := t.TempDir()
	applySetupPublicationACL(t, parent)
	cacheRoot := filepath.Join(parent, "InstallerCache")
	if err := os.Mkdir(cacheRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ValidatePrivateDirectory(cacheRoot); err == nil {
		t.Fatal("inherited Setup cache unexpectedly satisfied private custody before repair")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(self)
	if err != nil {
		t.Fatal(err)
	}
	maintenancePath := filepath.Join(cacheRoot, setupArtifactName)
	transaction := setupTransaction{
		MaintenancePath:   maintenancePath,
		MaintenanceNew:    maintenancePath + ".new." + strings.Repeat("a", 32),
		MaintenanceBackup: maintenancePath + ".backup." + strings.Repeat("a", 32),
		MaintenanceSHA256: digest,
	}
	if err := publishMaintenanceCopyForTransaction(transaction, true); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ValidatePrivateDirectory(cacheRoot); err != nil {
		t.Fatalf("published installer cache custody: %v", err)
	}
	if err := safefile.ValidatePrivateFile(maintenancePath); err != nil {
		t.Fatalf("published Setup custody: %v", err)
	}
	publishedDigest, err := fileSHA256(maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	if publishedDigest != digest {
		t.Fatalf("published Setup digest = %s, want %s", publishedDigest, digest)
	}
}
