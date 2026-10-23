// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-1493: the elevated lifecycle validates the installed CLI's custody
// before it builds a command for it. An image a standard user can replace is
// refused before any process is created.
func TestWindowsEnterpriseInstalledCLICustodyIsCheckedBeforeExec(t *testing.T) {
	newHotConfigHost(t, "config_version: 9\n", "config_version: 9\n")
	var checked string
	windowsEnterpriseInstalledCLICustody = func(path, _ string) error {
		checked = path
		return errors.New("BUILTIN\\Users can write the file")
	}
	command, err := windowsEnterprisePolicyDigestCommand(context.Background())
	if err == nil || command != nil || !strings.Contains(err.Error(), "refuse to run the installed CLI") {
		t.Fatalf("policy digest command = %v, %v; want the custody refusal", command, err)
	}
	if !strings.HasSuffix(strings.ToLower(checked), `\cisco\defenseclaw\bin\defenseclaw.exe`) {
		t.Fatalf("custody checked %q, want the installed CLI", checked)
	}
	windowsEnterpriseInstalledCLICustody = func(string, string) error { return nil }
	if command, err := windowsEnterprisePolicyDigestCommand(context.Background()); err != nil || command == nil {
		t.Fatalf("trusted image: command = %v, %v", command, err)
	}
}

// Review P1 (GAP-1493): Program Files\Cisco is an installer-owned root, so
// the shared trust walk only warns about a folder there that a standard
// user can delete children of. That user could swap defenseclaw.exe between
// the check and the elevated policy digest launch. The production custody
// check refuses it. Real ACLs, the real validator and the launch path; the
// fixture sits under ProgramData with an Administrators owner so the native
// CI runs it (see TestWindowsManagedRecordTrustUsesRealACLs).
func TestWindowsEnterpriseInstalledCLICustodyRefusesAReplaceableFolder(t *testing.T) {
	production := windowsEnterpriseInstalledCLICustody
	newHotConfigHost(t, "config_version: 9\n", "config_version: 9\n")
	windowsEnterpriseInstalledCLICustody = production
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Skipf("resolve ProgramData: %v", err)
	}
	root, err := os.MkdirTemp(programData, "dc-cli-custody-test-")
	if err != nil {
		t.Skipf("create a fixture under ProgramData: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	icacls := func(args ...string) error {
		out, err := exec.Command("icacls", args...).CombinedOutput()
		if err != nil {
			t.Logf("icacls %v: %v: %s", args, err, out)
		}
		return err
	}
	if err := icacls(root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"); err != nil {
		t.Skip("cannot set an administrator-only ACL here")
	}
	bin := filepath.Join(root, "Cisco", "DefenseClaw", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(bin, "defenseclaw.exe")
	if err := os.WriteFile(cli, []byte("stand-in"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := icacls(root, "/setowner", "*S-1-5-32-544", "/T", "/C"); err != nil {
		t.Skip("setting the Administrators owner needs an elevated shell")
	}
	// The fixture stands for Program Files: its Cisco folder is an
	// installer-owned root, as on a real host.
	t.Setenv("ProgramFiles", root)
	if !managed.PlatformInstallerOwnedPath(filepath.Join(root, "Cisco")) {
		t.Fatalf("%s must be installer-owned for this test", filepath.Join(root, "Cisco"))
	}
	resolver := windowsEnterpriseProgramFilesResolver
	t.Cleanup(func() { windowsEnterpriseProgramFilesResolver = resolver })
	windowsEnterpriseProgramFilesResolver = func() (string, error) { return root, nil }

	command, err := windowsEnterprisePolicyDigestCommand(context.Background())
	if err != nil || command == nil || !strings.EqualFold(command.Path, cli) {
		t.Fatalf("administrator-only image: command = %v, %v; want %s", command, err, cli)
	}
	// Add-file alone on bin cannot replace the image and stays accepted.
	if err := icacls(bin, "/grant", "*S-1-5-32-545:(WD)"); err != nil {
		t.Fatal(err)
	}
	if command, err := windowsEnterprisePolicyDigestCommand(context.Background()); err != nil || command == nil {
		t.Fatalf("add-file on bin: command = %v, %v; want it accepted", command, err)
	}
	// Delete-child on bin lets a standard user replace defenseclaw.exe.
	if err := icacls(bin, "/grant", "*S-1-5-32-545:(DC)"); err != nil {
		t.Fatal(err)
	}
	if !managed.TrustStrictAncestors() {
		// The shared walk only warns here: that is why the CLI needs its own.
		if err := managed.ValidateTrustedFilePath(cli, "installed DefenseClaw CLI"); err != nil {
			t.Fatalf("precondition: the shared walk refused the Cisco-tree drift: %v", err)
		}
	}
	command, err = windowsEnterprisePolicyDigestCommand(context.Background())
	if err == nil || command != nil || !strings.Contains(err.Error(), "refuse to run the installed CLI") {
		t.Fatalf("delete-child on bin: command = %v, %v; want the custody refusal", command, err)
	}
	var untrusted *managed.UntrustedPrincipalError
	if !errors.As(err, &untrusted) || !strings.EqualFold(untrusted.Path, bin) {
		t.Fatalf("refusal = %v, want it to name %s", err, bin)
	}
}
