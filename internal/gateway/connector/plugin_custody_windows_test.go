// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// GAP-0731: the refusal of a Windows plugin folder DACL carries the printed
// repair for every refused account; the rendering rows are in
// TestGAP0731IcaclsRemovalFix.
func TestGAP0731RefusalNamesTheCarrierAndTheIcaclsCommand(t *testing.T) {
	cause := &safefile.UnsafePrivateDACLError{
		Path: `C:\Users\lane\.config\opencode\plugins`,
		Entries: []safefile.UnsafeDACLEntry{
			{Trustee: `HOST\other`, Carriers: []string{`C:\Users\lane\.config\opencode`}},
			{Trustee: `HOST\third`, Carriers: []string{`C:\Users\lane\.config\opencode`}},
		},
	}
	err := explainPluginArtifactRefusal(`C:\Users\lane\.config\opencode\plugins\defenseclaw.js`, cause)
	if !errors.Is(err, ErrPluginFolderCustody) || !errors.Is(err, cause) {
		t.Fatalf("err=%v", err)
	}
	want := `fix: icacls 'C:\Users\lane\.config\opencode' /remove:g 'HOST\other'; icacls 'C:\Users\lane\.config\opencode' /remove:g 'HOST\third'`
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("message lacks %q:\n%v", want, err)
	}

	// Benign twins: a refusal naming no single entry, one naming an entry whose
	// folder cannot be found (a repair that leaves it would mislead), and any
	// other cause, are returned as they were.
	for _, other := range []error{
		&safefile.UnsafePrivateDACLError{Path: cause.Path},
		&safefile.UnsafePrivateDACLError{Path: cause.Path, Entries: []safefile.UnsafeDACLEntry{
			{Trustee: `HOST\other`, Carriers: []string{`C:\Users\lane\.config\opencode`}},
			{Trustee: `HOST\third`},
		}},
		errors.New("plugin target must be a regular file"),
	} {
		if got := explainPluginArtifactRefusal("", other); got != other {
			t.Fatalf("changed an unrelated refusal: %v", got)
		}
	}
}

// An existing plugin file with a foreign write entry is refused with the same
// explained fix as its folder (review 1 of GAP-0731).
func TestGAP0731PluginFileWithAForeignWriteEntryNamesTheIcaclsCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plugins")
	if _, err := safefile.CreatePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(dir, "defenseclaw.js")
	if err := os.WriteFile(plugin, []byte("// managed plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createOpenCodePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("a private plugin file was refused: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(plugin, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(plugin, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	err = createOpenCodePluginArtifactDestination(plugin)
	if err == nil || !errors.Is(err, ErrPluginFolderCustody) {
		t.Fatalf("err=%v, want a custody refusal with a fix", err)
	}
	if !strings.Contains(err.Error(), `icacls `+managed.PowerShellLiteral(plugin)+` /remove:g 'Everyone'`) {
		t.Fatalf("refusal lacks the icacls command for the plugin file:\n%v", err)
	}
}
