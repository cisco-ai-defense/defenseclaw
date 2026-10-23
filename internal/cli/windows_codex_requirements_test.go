// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestValidateWindowsStagedRetireGatewayLayout(t *testing.T) {
	const programData = `C:\ProgramData`
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileStandalone, `C:\Program Files`, programData)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(programData, "DefenseClaw-Enterprise-Setup-"+strings.Repeat("a", 32), "defenseclaw-gateway.exe")
	metadata := windowsCodexDeploymentMetadata{
		SchemaVersion:  1,
		DeploymentMode: "managed_enterprise",
		InstallRoot:    roots.InstallRoot,
		StateRoot:      roots.StateRoot,
	}
	cases := []struct {
		name       string
		executable string
		stateRoot  string
		mutate     func(*windowsCodexDeploymentMetadata)
		wantError  string
	}{
		{name: "verified Setup gateway", executable: stage, stateRoot: roots.StateRoot},
		{name: "protected payload folder gateway", executable: filepath.Join(programData, "DefenseClaw-Staging", "defenseclaw-gateway.exe"), stateRoot: roots.StateRoot},
		{name: "installed gateway", executable: filepath.Join(roots.InstallRoot, "bin", "defenseclaw-gateway.exe"), stateRoot: roots.StateRoot, wantError: "replacement gateway"},
		{name: "wrong state root", executable: stage, stateRoot: filepath.Join(programData, "other"), wantError: "matching installed deployment metadata"},
		{name: "wrong schema", executable: stage, stateRoot: roots.StateRoot, mutate: func(m *windowsCodexDeploymentMetadata) { m.SchemaVersion = 2 }, wantError: "matching installed deployment metadata"},
		{name: "wrong mode", executable: stage, stateRoot: roots.StateRoot, mutate: func(m *windowsCodexDeploymentMetadata) { m.DeploymentMode = "personal" }, wantError: "matching installed deployment metadata"},
		{name: "inactive install", executable: stage, stateRoot: roots.StateRoot, mutate: func(m *windowsCodexDeploymentMetadata) { inactive := false; m.Installed = &inactive }, wantError: "matching installed deployment metadata"},
		{name: "foreign install root", executable: stage, stateRoot: roots.StateRoot, mutate: func(m *windowsCodexDeploymentMetadata) { m.InstallRoot = filepath.Join(programData, "other") }, wantError: "install root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := metadata
			if tc.mutate != nil {
				tc.mutate(&current)
			}
			got, err := validateWindowsStagedRetireGatewayLayout(tc.executable, tc.stateRoot, current, roots)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("layout error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil || !sameWindowsEnterprisePathCLI(got, roots.InstallRoot) {
				t.Fatalf("layout root = %q, err=%v, want %q", got, err, roots.InstallRoot)
			}
		})
	}
}

// The staged retire runs the replacement gateway from the folder Setup or an
// administrator put the payload in. Every such folder that Setup's source
// descriptor admits is admitted here too; a folder or file another user can
// change is refused before the gateway runs any retire.
func TestValidateWindowsStagedRetireGatewayImage(t *testing.T) {
	for _, tc := range []struct{ name, executable string }{
		{name: "wrong executable", executable: `C:\ProgramData\DefenseClaw-Staging\defenseclaw-hook.exe`},
		{name: "relative source", executable: `payload\defenseclaw-gateway.exe`},
		{name: "noncanonical source", executable: `C:\ProgramData\DefenseClaw-Staging\..\DefenseClaw-Staging\defenseclaw-gateway.exe`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateWindowsStagedRetireGatewayImage(tc.executable); err == nil ||
				!strings.Contains(err.Error(), "exact replacement gateway path") {
				t.Fatalf("image error = %v, want the exact-path refusal", err)
			}
		})
	}

	// Folders below ProgramData are what Setup and the documented payload
	// folders use. Setup writes its stage as LocalSystem; an administrator's
	// payload folder must be owned by Administrators for Setup's source
	// descriptor too. Only an elevated test can give its folders that owner,
	// so an unelevated one runs only the refusals.
	elevated := windows.GetCurrentProcessToken().IsElevated()
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Fatal(err)
	}
	suffix := make([]byte, 16)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(programData, "DefenseClaw-Staging-test-"+hex.EncodeToString(suffix[:5]))
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	ownByAdministrators := func(t *testing.T, path string) {
		t.Helper()
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, administrators, nil, nil, nil); err != nil {
			t.Fatalf("own %s by Administrators: %v", path, err)
		}
	}
	const adminOnly = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// ProgramData's stock DACL without its CREATOR OWNER template: what an
	// administrator's payload folder keeps once its creator's own grant is
	// removed, including the Users create-file grant on folders.
	const programDataLike = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)"
	const usersModify = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)"
	setDACL := func(t *testing.T, path, sddl string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setDACL(t, root, programDataLike)
	cases := []struct {
		name      string
		folder    string
		folderACL string
		fileACL   string
		admitted  bool
	}{
		{name: "Setup stage", folder: filepath.Join(root, "DefenseClaw-Enterprise-Setup-"+hex.EncodeToString(suffix)), folderACL: adminOnly, admitted: true},
		{name: "payload folder with ProgramData's Users grants", folder: filepath.Join(root, "payload"), admitted: true},
		{name: "payload folder with a libexec folder", folder: filepath.Join(root, "pipeline", "libexec"), admitted: true},
		{name: "payload folder users can modify", folder: filepath.Join(root, "writable"), folderACL: usersModify},
		{name: "gateway file users can modify", folder: filepath.Join(root, "writable-file"), folderACL: adminOnly, fileACL: usersModify},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.admitted && !elevated {
				t.Skip("an unelevated account owns the payload folder it creates")
			}
			if err := os.MkdirAll(tc.folder, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.folderACL != "" {
				setDACL(t, tc.folder, tc.folderACL)
			}
			executable := filepath.Join(tc.folder, "defenseclaw-gateway.exe")
			if err := os.WriteFile(executable, []byte("gateway"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.fileACL != "" {
				setDACL(t, executable, tc.fileACL)
			}
			if elevated {
				for path := executable; ; path = filepath.Dir(path) {
					ownByAdministrators(t, path)
					if path == root {
						break
					}
				}
			}
			err := validateWindowsStagedRetireGatewayImage(executable)
			if tc.admitted && err != nil {
				t.Fatalf("documented payload folder refused: %v", err)
			}
			if !tc.admitted && err == nil {
				t.Fatalf("gateway another user can change was admitted: %s", executable)
			}
			// The resolver applies this check before it uses the gateway.
			_, resolveErr := resolveWindowsStagedRetireInstallRoot(executable)
			if resolveErr == nil {
				t.Fatal("resolver admitted a staged retire outside LocalSystem and standalone")
			}
			if !tc.admitted && resolveErr.Error() != err.Error() {
				t.Fatalf("resolver error = %v, want the image refusal %v", resolveErr, err)
			}
			if tc.admitted && strings.Contains(resolveErr.Error(), tc.folder) {
				t.Fatalf("resolver refused the admitted gateway: %v", resolveErr)
			}
		})
	}
}

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

func TestEnableWindowsCodexManifestTargetsUsesGuardianManifest(t *testing.T) {
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
				{Connector: "cursor"},
			},
		}, nil
	}

	var opts connector.WindowsCodexMachineRequirementsOptions
	if err := enableWindowsCodexManifestTargets(stateRoot, &opts); err != nil {
		t.Fatal(err)
	}
	if trustedPath != want || loadedPath != want {
		t.Fatalf("manifest trust/load paths = %q / %q, want exact %q", trustedPath, loadedPath, want)
	}
	if trustedPath == filepath.Join(stateRoot, "etc", "targets.yaml") {
		t.Fatal("legacy etc targets path must never be consulted")
	}
	if !opts.CodexTargetEnabled || !opts.ClaudeTargetEnabled || !opts.CursorTargetEnabled {
		t.Fatalf("manifest targets = %+v, want all three enabled", opts)
	}
}
