// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"os/exec"
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
	// The IDE inventory grants nothing on a guardian-owned .kiro either,
	// only below it (GAP-0897).
	ide := func(home string) map[string]bool {
		dirs := map[string]bool{}
		for _, g := range inventoryDACLIDEGrants(home, owned[strings.ToLower(home)]) {
			dirs[g.dir] = true
		}
		return dirs
	}
	if alice := ide(`C:\Users\Alice`); alice[".kiro"] || !alice[`.kiro\extensions`] {
		t.Fatalf("alice IDE grants on .kiro = %v, below = %v; want none on .kiro, one below", alice[".kiro"], alice[`.kiro\extensions`])
	}
	if !ide(`C:\Users\bob`)[".kiro"] {
		t.Fatal("bob lost the .kiro attributes grant")
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

// GAP-0156: the IDE grants reach a Remote-SSH server build's package.json
// and a %LOCALAPPDATA%\JetBrains product's plugins, but not the caches beside
// them, and nothing through a junction below the profile.
func TestInventoryDACLIDEGrantsStayNarrowAndRefuseLinks(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	home, outside := t.TempDir(), t.TempDir()
	write := func(path string) string {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	jar := write(filepath.Join(home, `AppData\Local\JetBrains\IntelliJIdea2025.2\plugins\ai\lib\ai.jar`))
	pkg := write(filepath.Join(home, `.vscode-server\cli\servers\Stable-0a1b\server\package.json`))
	caches := write(filepath.Join(home, `AppData\Local\JetBrains\IntelliJIdea2025.2\caches\content.dat`))
	privateState := write(filepath.Join(home, `AppData\Roaming\Code\User\globalStorage\agent.example\session.json`))
	legacyRoot := filepath.Join(home, `AppData\Roaming\Code\User\globalStorage`)
	if _, err := ensureInventoryReadACE(legacyRoot, sid); err != nil {
		t.Fatal(err)
	}
	linked := write(filepath.Join(outside, `AndroidStudio2025.1\plugins\x.jar`))
	google := filepath.Join(home, `AppData\Local\Google`)
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", google, outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	hasACE := func(path string) bool {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		return err == nil && dacl != nil && daclHasACEFor(dacl, []*windows.SID{sid})
	}
	for pass, want := range []inventoryDACLResult{inventoryDACLGranted, inventoryDACLAlreadyPresent} {
		for _, g := range inventoryDACLIDEGrants(home, nil) {
			result, err := g.ensure(filepath.Join(home, g.dir), sid)
			if g.dir == `AppData\Local\Google` {
				if !errors.Is(err, errInventoryDACLLink) {
					t.Fatalf("grant on the junction = %v, %v; want refused", result, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", g.dir, err)
			}
			if result != inventoryDACLSkippedMissing && result != want {
				t.Fatalf("pass %d %s = %v, want %v", pass, g.dir, result, want)
			}
		}
	}
	for path, want := range map[string]bool{jar: true, pkg: true, caches: false, filepath.Dir(caches): false, privateState: false, linked: false, outside: false} {
		if got := hasACE(path); got != want {
			t.Errorf("service ACE on %s = %v, want %v", path, got, want)
		}
	}
}

// GAP-0197: an agent folder a standard user replaced with a junction gets no
// grant from the standalone profile, and no ACE reaches the junction's target.
func TestInventoryDACLAgentGrantsRefuseLinksInTheStandaloneProfile(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	home, outside := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	claudeState := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(claudeState, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(home, ".claude"), outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	hasACE := func(path string) bool {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		return err == nil && dacl != nil && daclHasACEFor(dacl, []*windows.SID{sid})
	}
	for _, g := range inventoryDACLAgentGrants(home, nil, true) {
		result, err := g.ensure(filepath.Join(home, g.dir), sid)
		switch g.dir {
		case ".claude":
			if !errors.Is(err, errInventoryDACLLink) {
				t.Fatalf("grant on the junction = %v, %v; want refused", result, err)
			}
		case ".codex":
			if err != nil || result != inventoryDACLGranted {
				t.Fatalf(".codex = %v, %v; want granted", result, err)
			}
		case ".claude.json":
			if err != nil || result != inventoryDACLGranted {
				t.Fatalf(".claude.json = %v, %v; want granted", result, err)
			}
		}
	}
	if hasACE(outside) {
		t.Fatal("the junction's target gained the service ACE")
	}
	if !hasACE(filepath.Join(home, ".codex")) {
		t.Fatal("a plain agent folder lost its grant")
	}
	if !hasACE(claudeState) || hasACE(home) {
		t.Fatal("Claude state grant did not stay on the file")
	}
}

func TestInventoryDACLRejectsDirectoryReplacedAfterCheck(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	home, outside := t.TempDir(), t.TempDir()
	parent := filepath.Join(home, "AppData", "Local")
	dir := filepath.Join(parent, "cursor-agent")
	outsideDir := filepath.Join(outside, "cursor-agent")
	for _, path := range []string{dir, outsideDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previous := inventoryDACLAfterLinkCheck
	t.Cleanup(func() { inventoryDACLAfterLinkCheck = previous })
	inventoryDACLAfterLinkCheck = func() {
		inventoryDACLAfterLinkCheck = func() {}
		if err := os.RemoveAll(parent); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", parent, outside).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v: %s", err, out)
		}
	}
	var grant inventoryDACLGrant
	for _, candidate := range inventoryDACLAgentGrants(home, nil, true) {
		if candidate.dir == `AppData\Local\cursor-agent` {
			grant = candidate
			break
		}
	}
	result, err := grant.ensure(dir, sid)
	if result != inventoryDACLSkippedMissing || !errors.Is(err, errInventoryDACLLink) {
		t.Fatalf("swapped parent grant = %v, %v; want reparse refusal", result, err)
	}
	sd, err := windows.GetNamedSecurityInfo(outsideDir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || daclHasACEFor(dacl, []*windows.SID{sid}) {
		t.Fatalf("junction target gained the service ACE: %v", err)
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

// GAP-0913: the enumerator grants the gateway service read access to every
// skill and plugin folder the managed watcher watches for an enrolled user,
// except a folder on a managed hook path, which the guardian keeps at its
// exact DACL. Copilot, OpenCode and Amp skills were never granted, so the
// watcher could not read them and a skill there was never scanned.
func TestInventoryDACLComponentGrantsCoverWatchedFolders(t *testing.T) {
	ownHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home := `C:\Users\dc-gap0913`
	names := []string{"copilot", "opencode", "amp", "hermes"}
	granted := map[string]bool{}
	for _, g := range inventoryDACLComponentGrants(home, ownHome, inventoryDACLEnrolledHome{connectors: names}) {
		granted[strings.ToLower(g.dir)] = true
	}
	for _, want := range []string{`.copilot\skills`, `.config\opencode\skills`, `.config\amp\skills`} {
		if !granted[want] {
			t.Errorf("watched folder %s is not granted; granted %v", want, granted)
		}
	}
	for _, hookDir := range []string{`.copilot`, `.config`} {
		if granted[hookDir] {
			t.Errorf("folder %s on a managed hook path is granted", hookDir)
		}
	}
	// The Amp and OpenCode plugin folders are on their hook path and get
	// the read grant the guardian admits there (GAP-0958).
	for _, pluginRoot := range []string{`.config\amp\plugins`, `.config\opencode\plugins`} {
		if !granted[pluginRoot] {
			t.Errorf("plugin folder %s is not granted", pluginRoot)
		}
	}
	// The uninstall revokes every folder the enumerator grants.
	revoked := map[string]bool{}
	for _, rel := range inventoryDACLComponentDirs(home) {
		revoked[strings.ToLower(rel)] = true
	}
	for dir := range granted {
		if !revoked[dir] {
			t.Errorf("granted folder %s is not revoked at uninstall", dir)
		}
	}
	reg := connector.NewDefaultRegistry()
	var managed []string
	for _, name := range names {
		conn, _ := reg.Get(name)
		managed = append(managed, inventoryDACLManagedHookPaths(conn, home)...)
	}
	for _, name := range names {
		conn, _ := reg.Get(name)
		skills, plugins := connector.ComponentDirsForHome(conn, ownHome, home)
		for _, dir := range append(skills, plugins...) {
			rel, _ := filepath.Rel(home, dir)
			if !granted[strings.ToLower(rel)] && !inventoryDACLOnManagedPath(dir, managed) {
				t.Errorf("%s watches %s, which is neither granted nor on a managed hook path", name, rel)
			}
		}
	}
}

// GAP-0958: the Amp and OpenCode plugin folder is their managed hook path,
// at the guardian's exact protected DACL, and the folder where a user adds a
// plugin. The enumerator adds the gateway service's read grant there; the
// guardian's exact check admits it on that folder only, and only read
// rights. DefenseClaw's own plugin keeps its protected DACL, a plugin the
// user had added inherits the grant, and the uninstall revoke restores the
// exact DACL.
func TestGatewayPluginRootReadGrantKeepsTheGuardianDACL(t *testing.T) {
	if ok, err := windowsTestEffectiveAdministratorsEnabled(); err != nil || !ok {
		t.Skip("granting needs WRITE_DAC through the Administrators entry of the guardian DACL")
	}
	target := currentWindowsTestSID(t)
	gateway, err := windowsGatewayPluginRootReadSID()
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "home")
	rel := `.config\amp\plugins`
	root := filepath.Join(home, rel)
	sibling := filepath.Join(home, `.config\amp\skills`)
	userPlugin := filepath.Join(root, "user-plugin")
	for _, dir := range []string{root, sibling, userPlugin} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	managedPlugin := filepath.Join(root, "defenseclaw.ts")
	if err := os.WriteFile(managedPlugin, []byte("// plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pluginACL, err := windowsManagedPluginProtectionACL(target, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(managedPlugin, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, pluginACL, nil); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{root, sibling} {
		if err := setWindowsUserPathProtection(dir, target, true); err != nil {
			t.Fatal(err)
		}
	}
	dacl := func(path string) *windows.ACL {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil {
			t.Fatalf("DACL of %s: %v", path, err)
		}
		return acl
	}
	ownHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	var grant *inventoryDACLGrant
	for _, g := range inventoryDACLComponentGrants(home, ownHome, inventoryDACLEnrolledHome{sid: target.String(), connectors: []string{"amp"}}) {
		if strings.EqualFold(g.dir, rel) {
			grant = &g
		}
	}
	if grant == nil {
		t.Fatalf("the enumerator does not grant %s", rel)
	}
	for pass, want := range []inventoryDACLResult{inventoryDACLGranted, inventoryDACLAlreadyPresent} {
		got, err := grant.ensure(root, gateway)
		if err != nil || got != want {
			t.Fatalf("pass %d = %v, %v; want %v", pass, got, err, want)
		}
	}
	if err := validateWindowsUserPathElement(root, target, true, true, true); err != nil {
		t.Fatalf("guardian exact check refuses the granted plugin folder: %v", err)
	}
	const writeLike = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40 // FILE_DELETE_CHILD
	acl := dacl(root)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(gateway) && ace.Mask&writeLike != 0 {
			t.Fatalf("gateway entry has write-like rights 0x%x", uint32(ace.Mask))
		}
	}
	if !daclContainsInventoryReadACE(dacl(userPlugin), gateway) {
		t.Fatal("the plugin the user added does not inherit the gateway read grant")
	}
	if daclHasACEFor(dacl(managedPlugin), []*windows.SID{gateway}) {
		t.Fatal("the managed plugin inherited the gateway grant")
	}
	if err := verifyWindowsPrivatePluginFile(managedPlugin, target, true); err != nil {
		t.Fatalf("managed plugin DACL changed: %v", err)
	}
	// The guardian DACL plus any other gateway entry, or the read grant on
	// any other guardian folder, is still drift.
	withGatewayEntry := func(path string, mask windows.ACCESS_MASK) {
		t.Helper()
		canonical, err := windowsUserPathCanonicalACEs(target, true)
		if err != nil {
			t.Fatal(err)
		}
		canonical = append(canonical, windowsUserPathCanonicalACE{sid: gateway, mask: mask, inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT})
		entries := make([]windows.EXPLICIT_ACCESS, 0, len(canonical))
		for _, item := range canonical {
			entries = append(entries, windows.EXPLICIT_ACCESS{AccessPermissions: item.mask, AccessMode: windows.GRANT_ACCESS,
				Inheritance: item.inheritance, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID,
					TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(item.sid)}})
		}
		acl, err := windows.ACLFromEntries(entries, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	withGatewayEntry(sibling, inventoryReadACE.mask)
	if err := validateWindowsUserPathElement(sibling, target, true, true, true); err == nil {
		t.Fatal("guardian exact check admits the gateway grant outside the plugin folder")
	}
	withGatewayEntry(root, inventoryReadACE.mask|windows.GENERIC_WRITE)
	if err := validateWindowsUserPathElement(root, target, true, true, true); err == nil {
		t.Fatal("guardian exact check admits a writable gateway entry on the plugin folder")
	}
	if got, err := ensureGatewayPluginRootReadACEPinned(home, rel, gateway, target); err != nil || got != inventoryDACLSkippedMissing {
		t.Fatalf("grant over a drifted plugin folder = %v, %v; want it left to the guardian", got, err)
	}
	if err := setWindowsUserPathProtection(root, target, true); err != nil {
		t.Fatal(err)
	}
	if got, err := ensureGatewayPluginRootReadACEPinned(home, rel, gateway, target); err != nil || got != inventoryDACLGranted {
		t.Fatalf("grant after the guardian reset = %v, %v", got, err)
	}
	// The uninstall revoke leaves the exact guardian DACL.
	if err := revokeInventoryACEs(root, []*windows.SID{gateway}); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsUserPathElement(root, target, true, true, true); err != nil {
		t.Fatalf("revoked plugin folder is not at the guardian DACL: %v", err)
	}
	if daclHasACEFor(dacl(root), []*windows.SID{gateway}) {
		t.Fatal("revoke left a gateway entry on the plugin folder")
	}
}
