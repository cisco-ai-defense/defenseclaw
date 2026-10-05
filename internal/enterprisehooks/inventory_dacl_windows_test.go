// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// GAP-1210: the guardian keeps an enrolled Kiro user's .kiro at its exact
// protected DACL, so the inventory grant skips it there.
func TestInventoryDACLSkipsKiroWhereTheGuardianOwnsIt(t *testing.T) {
	disabled := false
	manifest := Manifest{Targets: []ManifestTarget{
		{UserHome: `C:\Users\Alice`, Connector: "kiro"},
		{UserHome: `C:\Users\Alice`, Connector: "codex"},
		{UserHome: `C:\Users\bob`, Connector: "codex"},
		{UserHome: `C:\Users\carol`, Connector: "kiro", Enabled: &disabled},
	}}
	owned := inventoryDACLGuardianOwnedByHome(manifest)
	if _, ok := owned[`c:\users\alice`][".kiro"]; !ok {
		t.Fatalf("alice's .kiro is not guardian-owned: %v", owned)
	}
	for _, home := range []string{`c:\users\bob`, `c:\users\carol`} {
		if _, ok := owned[home][".kiro"]; ok {
			t.Fatalf("%s's .kiro is guardian-owned: %v", home, owned)
		}
	}
}

// GAP-1863: every inventory folder that holds an enrolled per-user
// connector's hook config or managed footprint (Amp and OpenCode under
// .config, Antigravity under .gemini) is guardian-owned for that user, so the enumerator does not grant
// a folder the next ensure resets to its protected DACL.
func TestInventoryDACLSkipsEveryPerUserHookPathFolder(t *testing.T) {
	home := t.TempDir()
	granted := map[string]bool{}
	for _, dir := range inventoryDACLDotdirs {
		granted[strings.ToLower(dir)] = true
	}
	reg := connector.NewDefaultRegistry()
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		conn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("connector %s is not registered", name)
		}
		var paths []string
		if err := connector.WithUserHomeDir(home, func() error {
			setup := connector.SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"), ManagedEnterprise: true}
			paths = connector.HookConfigPathsForConnector(conn, setup)
			if provider, ok := conn.(connector.AgentPathProvider); ok {
				footprint := provider.AgentPaths(setup)
				for _, group := range [][]string{footprint.PatchedFiles, footprint.GeneratedFiles, footprint.GeneratedExecutables, footprint.CreatedDirs} {
					paths = append(paths, group...)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		owned := inventoryDACLGuardianOwnedByHome(Manifest{Targets: []ManifestTarget{{UserHome: home, Connector: name}}})[strings.ToLower(home)]
		for _, path := range paths {
			rel, err := filepath.Rel(home, path)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			first := strings.Split(rel, string(filepath.Separator))[0]
			if !granted[strings.ToLower(first)] {
				continue
			}
			if _, ok := owned[first]; !ok {
				t.Errorf("%s managed path %s is under granted folder %s, which is not guardian-owned for it", name, rel, first)
			}
		}
	}
	owned := inventoryDACLGuardianOwnedByHome(Manifest{Targets: []ManifestTarget{{UserHome: home, Connector: "codex"}}})
	if len(owned) != 0 {
		t.Fatalf("a codex-only home owns %v", owned)
	}
}

// GAP-1863: Windows splits the read grant into a folder ACE and an
// inherit-only ACE, and the next pass must see it as already present.
func TestEnsureInventoryReadACEIsIdempotent(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), ".claude")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for pass, want := range []inventoryDACLResult{inventoryDACLGranted, inventoryDACLAlreadyPresent, inventoryDACLAlreadyPresent} {
		result, err := ensureInventoryReadACE(dir, sid)
		if err != nil {
			t.Fatal(err)
		}
		if result != want {
			t.Fatalf("pass %d result = %v, want %v", pass, result, want)
		}
	}
	// A subfolder covered by the inherited grant is already present too.
	child := filepath.Join(dir, "skills")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if result, err := ensureInventoryReadACE(child, sid); err != nil || result != inventoryDACLAlreadyPresent {
		t.Fatalf("child result = %v, %v; want already present", result, err)
	}
}

// The Kiro CLI install folder gets list rights on the folder itself only.
func TestEnsureInventoryListACEGrantsTheFolderOnly(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "Kiro-Cli")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for pass, want := range []inventoryDACLResult{inventoryDACLGranted, inventoryDACLAlreadyPresent} {
		result, err := ensureInventoryListACE(dir, sid)
		if err != nil {
			t.Fatal(err)
		}
		if result != want {
			t.Fatalf("pass %d result = %v, want %v", pass, result, want)
		}
	}
	child := filepath.Join(dir, "data.sqlite3")
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{dir: true, child: false} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for i := uint32(0); dacl != nil && i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				t.Fatal(err)
			}
			if windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), sid) {
				found = true
				if ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0 {
					t.Fatalf("list ACE on %s inherits: flags 0x%x", path, ace.Header.AceFlags)
				}
			}
		}
		if found != want {
			t.Fatalf("service ACE on %s = %v, want %v", path, found, want)
		}
	}
}

// Copilot CLI and Devin CLI keep their hook files on the guardian's protected
// path, so, like Kiro CLI, they are discovered through list-only grants on
// their install folders (GAP-1739). Those folders are never on a hook path.
func TestInventoryListOnlyDirsCoverGuardianProtectedAgents(t *testing.T) {
	want := map[string]bool{`AppData\Local\Kiro-Cli`: true, `AppData\Local\copilot\pkg`: true, `AppData\Local\devin\cli`: true,
		`AppData\Roaming\npm\node_modules\@ampcode\cli`: true, `AppData\Local\cursor-agent`: true}
	for _, dir := range inventoryDACLListOnlyDirs {
		delete(want, dir)
		for _, dotdir := range inventoryDACLDotdirs {
			if strings.EqualFold(dir, dotdir) {
				t.Fatalf("%s has both an inherited and a list-only grant", dir)
			}
		}
	}
	if len(want) != 0 {
		t.Fatalf("list-only grants miss %v", want)
	}
}
