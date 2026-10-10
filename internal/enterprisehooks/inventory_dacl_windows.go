// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// inventoryDACLDotdirs enumerates the top-level user-profile subdirectories the
// AI discovery scanner walks for skill, plugin, rule, and MCP-config signatures.
// Kept in sync with the catalog under internal/inventory/ai_signatures.json —
// this list covers the ancestor traversal that the scanner needs. Child ACEs
// inherit from these parents via SUB_CONTAINERS_AND_OBJECTS_INHERIT so
// per-file reads don't need a separate grant. The IDE plugin inventory's
// folders are granted apart from these (inventoryDACLIDEGrants).
var inventoryDACLDotdirs = append([]string{
	".claude",
	".codex",
	".cursor",
	".gemini",
	// Antigravity CLI's own folder (skills, plugins). It is not on the
	// Antigravity hook path, so it is granted even where the guardian owns
	// .gemini (GAP-1863).
	`.gemini\antigravity-cli`,
	".openhands",
	".openclaw",
	".hermes",
	".amp",
	".opencode",
	".agents",
	".config",
	".kiro",
	// Hermes keeps its home in %LOCALAPPDATA%\hermes on Windows. Only its
	// skills and plugins folders are granted: the home also holds the
	// agent's install (about 130,000 objects), which an inherited grant
	// would rewrite on every account. Without them the scanner never found
	// Hermes for any user.
	`AppData\Local\hermes\skills`,
	`AppData\Local\hermes\plugins`,
}, legacyconnector.InventoryDotDirs...)

// inventoryDACLGuardianOwnedDotdirs maps a dotdir to the connectors whose
// enrollment puts it on that user's managed hook path (Kiro: .kiro\settings;
// Amp and OpenCode: .config\<agent>\plugins; Antigravity:
// .gemini\config\hooks.json). The guardian keeps every element of that path
// at its exact protected DACL, so an inventory grant there is drift that the
// next ensure or repair removes, and the protected children never inherit
// it. Such a dotdir is not granted while the user has an enabled row for one
// of its connectors (GAP-1210, GAP-1863).
var inventoryDACLGuardianOwnedDotdirs = map[string][]string{
	".kiro":   {"kiro"},
	".config": {"amp", "opencode"},
	".gemini": {"antigravity"},
}

// inventoryDACLListOnlyDirs are per-user install folders the scanner only
// needs to see. The service gets list and read-attributes rights on the
// folder itself, with no inheritance, so it can tell the agent is installed
// without reading what the folder holds. Kiro CLI installs into
// %LOCALAPPDATA%\Kiro-Cli, whose data.sqlite3 holds the user's session and
// sign-in state; this is how a user whose .kiro the guardian protects is
// still discovered. Copilot CLI and Devin CLI are the same case: their hook
// files (.copilot\hooks, AppData\Roaming\devin\config.json) put those
// folders on the guardian's protected path, so the service sees their
// install folders instead, Copilot CLI's package cache and Devin CLI's
// install (GAP-1739). Amp keeps its settings in .config\amp, which stays
// protected for a user enrolled for Amp, so the service sees its npm install
// folder (GAP-1963). Cursor's hooks are machine-level on a managed computer,
// so a user without ~\.cursor\mcp.json is seen by cursor-agent's install
// folder (GAP-1739).
var inventoryDACLListOnlyDirs = []string{
	`AppData\Local\Kiro-Cli`,
	`AppData\Local\copilot\pkg`,
	`AppData\Local\devin\cli`,
	`AppData\Roaming\npm\node_modules\@ampcode\cli`,
	`AppData\Local\cursor-agent`,
}

// gatewayServiceNamePattern matches the certification-scoped gateway service
// name. The scope suffix (10 lowercase hex chars) is generated at install time
// and shared across CertGateway/CertGuardian/CertEnumerator/CertCMIDBroker.
var gatewayServiceNamePattern = regexp.MustCompile(`^DefenseClawCertGateway_[a-f0-9]{10}$`)

// productionGatewayServiceName is the un-scoped gateway service name used by
// production installs (no cert suffix).
const productionGatewayServiceName = "DefenseClawGateway"

// GrantGatewayInventoryReadForManifest ensures the DefenseClaw CertGateway
// service's virtual service account has Read+Execute+Traverse ACEs on the
// inventory-relevant dotdirs under each enrolled user's profile. The gateway
// runs under NT SERVICE\DefenseClawCertGateway_<scope>, a virtual service
// account with no implicit access to user profiles; without this grant the AI
// discovery scanner walks the right paths but ReadDir returns "access denied"
// and every skill/plugin/rule/mcp_server signal is silently suppressed.
//
// Idempotent: SetEntriesInAcl merges by trustee, so repeated ticks with the
// same ACE parameters land byte-identical DACLs. Dotdirs that don't exist yet
// are skipped (the user may not have started that CLI yet); the next tick
// re-tries. Per-directory errors are logged and do not abort the pass — one
// user's misconfigured DACL should not block enrollment for the other users.
//
// ideInventory adds the IDE plugin inventory's folders (inventoryDACLIDEGrants).
// The Secure Client profile passes false: its gateway keeps the historical
// editor-extension detector and has no IDE inventory, so it gets no more
// access than it always had.
//
// If gatewayServiceName is empty, discovers it via SCM enumeration (matches
// the cert-scoped or production naming). Returns an error only if the pass
// cannot even begin (SCM unavailable, service SID resolution fails); per-path
// failures are logged and swallowed.
func GrantGatewayInventoryReadForManifest(manifest Manifest, gatewayServiceName string, ideInventory bool, logf EnumerationLogger) error {
	name := strings.TrimSpace(gatewayServiceName)
	if name == "" {
		discovered, err := discoverGatewayServiceName()
		if err != nil {
			return fmt.Errorf("enterprise hooks: discover gateway service name: %w", err)
		}
		name = discovered
	}
	if !gatewayServiceNamePattern.MatchString(name) && name != productionGatewayServiceName {
		return fmt.Errorf("enterprise hooks: refusing untrusted gateway service name %q", name)
	}
	account := `NT SERVICE\` + name
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve gateway service SID %q: %w", account, err)
	}
	if !sidIsNTServiceInventory(sid) {
		return fmt.Errorf("enterprise hooks: gateway service account %q did not resolve to NT SERVICE authority", account)
	}

	granted, skipped, failed := 0, 0, 0
	guardianOwned := inventoryDACLGuardianOwnedByHome(manifest)
	enrolled := inventoryDACLEnrolledByHome(manifest)
	ownHome, _ := os.UserHomeDir()
	seenHome := map[string]struct{}{}
	for _, target := range manifest.Targets {
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if home == "" {
			continue
		}
		key := strings.ToLower(home)
		if _, dup := seenHome[key]; dup {
			continue
		}
		seenHome[key] = struct{}{}
		// The standalone profile (ideInventory) refuses links on the agent
		// folders as it does on the IDE folders; the Secure Client profile
		// keeps the grants it always made.
		grants := inventoryDACLAgentGrants(home, guardianOwned[key], ideInventory)
		if ideInventory {
			grants = append(grants, inventoryDACLComponentGrants(home, ownHome, enrolled[key])...)
			grants = append(grants, inventoryDACLIDEGrants(home, guardianOwned[key])...)
		}
		for _, g := range grants {
			dotdir := g.dir
			path := filepath.Join(home, dotdir)
			result, err := g.ensure(path, sid)
			switch {
			case err != nil:
				failed++
				// Log only the dotdir identifier and a sanitized error
				// category, never the absolute path (`C:\Users\<name>\.claude`)
				// or the wrapped Windows error text — the CLI enumeration
				// logger writes this verbatim to stderr and the target's SID
				// is already captured as the log-line prefix.
				logfSafely(logf, target.SID, fmt.Sprintf("inventory-DACL grant dotdir=%s: %s", dotdir, sanitizeInventoryDACLError(err)))
			case result == inventoryDACLGranted:
				granted++
			case result == inventoryDACLAlreadyPresent:
				skipped++
			}
		}
	}
	logfSafely(logf, "", fmt.Sprintf("inventory-DACL pass gateway=%s granted=%d already_present=%d failed=%d", name, granted, skipped, failed))
	return nil
}

// inventoryDACLGuardianOwnedByHome returns, per lowercased home, the dotdirs
// the guardian owns there (inventoryDACLGuardianOwnedDotdirs).
func inventoryDACLGuardianOwnedByHome(manifest Manifest) map[string]map[string]struct{} {
	owned := map[string]map[string]struct{}{}
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		home := strings.ToLower(filepath.Clean(strings.TrimSpace(target.UserHome)))
		for dotdir, connectorNames := range inventoryDACLGuardianOwnedDotdirs {
			for _, connectorName := range connectorNames {
				if !strings.EqualFold(strings.TrimSpace(target.Connector), connectorName) {
					continue
				}
				if owned[home] == nil {
					owned[home] = map[string]struct{}{}
				}
				owned[home][dotdir] = struct{}{}
			}
		}
	}
	return owned
}

// inventoryDACLEnrolledHome is what one profile is enrolled for: its
// account and the connectors of its enabled rows.
type inventoryDACLEnrolledHome struct {
	sid        string
	connectors []string
}

// inventoryDACLEnrolledByHome returns, per lowercased home, the account and
// the connectors of that home's enabled manifest rows.
func inventoryDACLEnrolledByHome(manifest Manifest) map[string]inventoryDACLEnrolledHome {
	out := map[string]inventoryDACLEnrolledHome{}
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		key := strings.ToLower(filepath.Clean(strings.TrimSpace(target.UserHome)))
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		if key == "" || key == "." || name == "" {
			continue
		}
		home := out[key]
		if home.sid == "" {
			home.sid = strings.TrimSpace(target.SID)
		}
		home.connectors = append(home.connectors, name)
		out[key] = home
	}
	return out
}

// inventoryDACLComponentGrants lists the skill and plugin folders the managed
// gateway's watcher watches for the connectors enrolled in home: the same
// list (connector.ComponentDirsForHome), with the inherited read ACE, so a
// skill added later is readable too. The dotdir grants above miss most of
// them: ~\.copilot, ~\.config\opencode\skills, ~\.config\amp\skills,
// ~\.config\agents\skills and Hermes' bundled plugins sit below a folder on
// a managed hook path or outside the granted dotdirs, so the watcher logged
// "Access is denied" and never scanned a skill there (GAP-0913). A folder
// on an enrolled connector's managed hook path is left out, as is one whose
// DACL is already the guardian's exact protected DACL: the guardian resets
// a grant there (GAP-1210). The Amp and OpenCode plugin folders are the
// exception: at the guardian's exact DACL, on their hook path or not, they
// get the one read grant that DACL admits there
// (ensureGatewayPluginRootReadACEPinned, GAP-0958). Nothing is granted
// through a link.
func inventoryDACLComponentGrants(home, ownHome string, enrolled inventoryDACLEnrolledHome) []inventoryDACLGrant {
	if strings.TrimSpace(ownHome) == "" || len(enrolled.connectors) == 0 {
		return nil
	}
	reg := connector.NewDefaultRegistry()
	var managed []string
	var dirs []string
	// Connector paths resolve through a process-wide home override; hold it
	// at this process profile so no other user resolution interleaves.
	_ = connector.WithUserHomeDir(ownHome, func() error {
		for _, name := range enrolled.connectors {
			if conn, ok := reg.Get(name); ok {
				skills, plugins := connector.ComponentDirsForHome(conn, ownHome, home)
				dirs = append(append(dirs, skills...), plugins...)
			}
		}
		return nil
	})
	for _, name := range enrolled.connectors {
		if conn, ok := reg.Get(name); ok {
			managed = append(managed, inventoryDACLManagedHookPaths(conn, home)...)
		}
	}
	target, _ := windows.StringToSid(enrolled.sid)
	seen := map[string]struct{}{}
	var grants []inventoryDACLGrant
	for _, dir := range dirs {
		rel, err := filepath.Rel(home, dir)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) || filepath.IsAbs(rel) {
			continue
		}
		key := strings.ToLower(rel)
		if _, dup := seen[key]; dup {
			continue
		}
		pluginRoot := windowsGatewayReadablePluginRoot(dir)
		onManagedPath := inventoryDACLOnManagedPath(dir, managed)
		if onManagedPath && !pluginRoot {
			continue
		}
		seen[key] = struct{}{}
		grants = append(grants, inventoryDACLGrant{dir: rel, ensure: func(_ string, sid *windows.SID) (inventoryDACLResult, error) {
			if target != nil && inventoryDACLGuardianProtected(filepath.Join(home, rel), target) {
				if pluginRoot {
					return ensureGatewayPluginRootReadACEPinned(home, rel, sid, target)
				}
				return inventoryDACLSkippedMissing, nil
			}
			if onManagedPath {
				return inventoryDACLSkippedMissing, nil
			}
			return ensureInventoryACEPinned(home, rel, sid, inventoryReadACE)
		}})
	}
	return grants
}

// inventoryDACLManagedHookPaths lists the files and folders the guardian
// keeps at their exact protected DACL for conn in home: its hook config and
// managed footprint.
func inventoryDACLManagedHookPaths(conn connector.Connector, home string) []string {
	var paths []string
	_ = connector.WithUserHomeDir(home, func() error {
		setup := connector.SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"), ManagedEnterprise: true}
		paths = connector.HookConfigPathsForConnector(conn, setup)
		if provider, ok := conn.(connector.AgentPathProvider); ok {
			footprint := provider.AgentPaths(setup)
			for _, group := range [][]string{footprint.PatchedFiles, footprint.GeneratedFiles, footprint.GeneratedExecutables, footprint.CreatedDirs} {
				paths = append(paths, group...)
			}
		}
		return nil
	})
	return paths
}

// inventoryDACLOnManagedPath reports whether dir is one of the managed paths
// or a folder on the way to one.
func inventoryDACLOnManagedPath(dir string, managed []string) bool {
	for _, path := range managed {
		if strings.TrimSpace(path) == "" {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
		if err == nil && rel != ".." && !strings.HasPrefix(rel, `..\`) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}

// inventoryDACLGuardianProtected reports whether path carries the guardian's
// exact protected DACL for target.
func inventoryDACLGuardianProtected(path string, target *windows.SID) bool {
	extended, err := winpath.Extended(path)
	if err != nil {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	return validateWindowsUserPathProtectionACL(path, sd, dacl, target, true) == nil
}

// inventoryDACLGrant is one path of a profile, relative to it, and how it is
// granted.
type inventoryDACLGrant struct {
	dir    string
	ensure func(string, *windows.SID) (inventoryDACLResult, error)
}

// inventoryDACLAgentGrants lists the agent folders (read, inherited) and the
// list-only install folders of one profile, leaving out the dotdirs the
// guardian owns there. With rejectLinks nothing is granted through a link or
// other reparse point below the profile: a standard user who replaced
// ~\.claude with a junction to a folder SYSTEM can modify would otherwise give
// the gateway service a read ACE on that folder at the next enumerator cycle,
// because the grant stats and sets the DACL by name, and both follow the link
// (GAP-0197).
func inventoryDACLAgentGrants(home string, guardianOwned map[string]struct{}, rejectLinks bool) []inventoryDACLGrant {
	grant := func(rel string, ensure func(string, *windows.SID) (inventoryDACLResult, error), kind inventoryACE) inventoryDACLGrant {
		if !rejectLinks {
			return inventoryDACLGrant{rel, ensure}
		}
		return inventoryDACLGrant{rel, func(_ string, sid *windows.SID) (inventoryDACLResult, error) {
			return ensureInventoryACEPinned(home, rel, sid, kind)
		}}
	}
	grants := make([]inventoryDACLGrant, 0, len(inventoryDACLDotdirs)+len(inventoryDACLListOnlyDirs))
	for _, dotdir := range inventoryDACLDotdirs {
		if _, owned := guardianOwned[dotdir]; !owned {
			grants = append(grants, grant(dotdir, ensureInventoryReadACE, inventoryReadACE))
		}
	}
	for _, dir := range inventoryDACLListOnlyDirs {
		grants = append(grants, grant(dir, ensureInventoryListACE, inventoryListACE))
	}
	if rejectLinks {
		// Claude Code writes user and local-scope MCP servers in this
		// profile-root file. Grant the standalone gateway this file alone;
		// no grant is inherited by its neighbours in the profile root.
		grants = append(grants, grant(".claude.json", ensureInventorySelfACE, inventorySelfACE))
	}
	return grants
}

// inventoryDACLIDEGrants lists the IDE folders and files of one profile that
// the gateway's IDE plugin inventory reads (ideplugins.WindowsHomeGrants):
// the same sources a per-user scan reads, Remote-SSH servers,
// %LOCALAPPDATA%\JetBrains and Android Studio included. Without them a
// managed host listed no IDE plugin for anyone (GAP-0042), and then none
// from those folders (GAP-0156). A folder whose content the scan reads gets
// the inherited read ACE; a folder it only lists, or one metadata file it
// reads, gets a read ACE on that object alone, so the caches and other data
// beside them stay out of reach. Nothing is granted through a link or other
// reparse point below the profile, nor on a dotdir the guardian owns there
// (the .kiro folder of a user enrolled for Kiro): the guardian keeps that
// folder at its exact protected DACL, so the next ensure removed the grant
// and the Kiro installation went missing from the inventory until the next
// cycle (GAP-0897). The scan reads below such a folder without it.
func inventoryDACLIDEGrants(home string, guardianOwned map[string]struct{}) []inventoryDACLGrant {
	var grants []ideplugins.WindowsGrant
	for _, g := range ideplugins.WindowsHomeGrants(home) {
		if _, owned := guardianOwned[g.Path]; !owned {
			grants = append(grants, g)
		}
	}
	out := make([]inventoryDACLGrant, 0, len(grants))
	for _, rel := range ideplugins.WindowsLegacyBroadGrants(home) {
		rel := rel
		out = append(out, inventoryDACLGrant{dir: rel, ensure: func(path string, sid *windows.SID) (inventoryDACLResult, error) {
			return revokeInventoryLegacyReadACEPinned(home, rel, sid)
		}})
	}
	for _, g := range grants {
		kind := inventorySelfACE
		if g.Tree {
			kind = inventoryReadACE
		} else if g.Attributes {
			kind = inventoryAttributesACE
		}
		rel := g.Path
		out = append(out, inventoryDACLGrant{dir: rel, ensure: func(_ string, sid *windows.SID) (inventoryDACLResult, error) {
			return ensureInventoryACEPinned(home, rel, sid, kind)
		}})
	}
	return out
}

// errInventoryDACLLink reports a link or other reparse point on the way to a
// grant: following it would grant the gateway another folder.
var errInventoryDACLLink = errors.New("reparse point below the profile")

// inventoryDACLRejectLinkBelow fails when any existing element of home\rel
// below home is a reparse point. Missing elements pass: the grant then
// skips the missing path.
func inventoryDACLRejectLinkBelow(home, rel string) error {
	current := home
	for _, part := range strings.Split(rel, `\`) {
		current = filepath.Join(current, part)
		ptr, err := winpath.UTF16Ptr(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(ptr)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		if err != nil {
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errInventoryDACLLink
		}
	}
	return nil
}

// inventoryDACLAfterLinkCheck is a test seam for a directory replacement
// between the path walk and the handle open.
var inventoryDACLAfterLinkCheck = func() {}

// openInventoryDACLHandle pins the object whose DACL will change. The final
// path must equal the requested child of the pinned profile even if a parent
// was replaced with a junction after the path walk.
func openInventoryDACLHandle(home, rel string) (windows.Handle, error) {
	return openWindowsProfileChildNoFollow(home, rel, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
}

// openWindowsProfileChildNoFollow opens home\rel with access and share as
// the object itself, never what a reparse point names. It fails with
// errInventoryDACLLink when an existing element below home is a reparse
// point, or when the opened objects final path is not homes followed by
// rel, which catches a parent swapped for a junction after the path walk.
// The inventory grants and revokes and the ACP purge (GAP-1256) pin their
// objects with it.
func openWindowsProfileChildNoFollow(home, rel string, access, share uint32) (windows.Handle, error) {
	if err := inventoryDACLRejectLinkBelow(home, rel); err != nil {
		return 0, err
	}
	inventoryDACLAfterLinkCheck()
	open := func(path string, access, share uint32) (windows.Handle, error) {
		ptr, err := winpath.UTF16Ptr(path)
		if err != nil {
			return 0, err
		}
		return windows.CreateFile(ptr, access, share, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	}
	homeHandle, err := open(home, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(homeHandle)
	var homeInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(homeHandle, &homeInfo); err != nil {
		return 0, err
	}
	if homeInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		homeInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return 0, errInventoryDACLLink
	}
	target, err := open(filepath.Join(home, rel), access, share)
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(target, &info); err != nil {
		windows.CloseHandle(target)
		return 0, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(target)
		return 0, errInventoryDACLLink
	}
	homePath, err := inventoryDACLFinalPath(homeHandle)
	if err != nil {
		windows.CloseHandle(target)
		return 0, err
	}
	targetPath, err := inventoryDACLFinalPath(target)
	if err != nil {
		windows.CloseHandle(target)
		return 0, err
	}
	if !strings.EqualFold(targetPath, filepath.Clean(filepath.Join(homePath, rel))) {
		windows.CloseHandle(target)
		return 0, errInventoryDACLLink
	}
	return target, nil
}

func inventoryDACLFinalPath(handle windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", errors.New("inventory DACL final path exceeds Windows path limit")
	}
	return filepath.Clean(windows.UTF16ToString(buf[:n])), nil
}

type inventoryDACLResult int

const (
	inventoryDACLSkippedMissing inventoryDACLResult = iota
	inventoryDACLGranted
	inventoryDACLAlreadyPresent
)

// inventoryACE is one kind of inventory grant.
type inventoryACE struct {
	mask        windows.ACCESS_MASK
	inheritance uint32
	// files lets the grant go on a regular file as well as on a folder.
	files   bool
	present func(*windows.ACL, *windows.SID) bool
}

var (
	inventoryReadACE = inventoryACE{
		mask: windows.GENERIC_READ | windows.GENERIC_EXECUTE, inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		present: daclContainsInventoryReadACE,
	}
	inventoryListACE = inventoryACE{
		mask: inventoryListMask, inheritance: windows.NO_INHERITANCE,
		present: daclContainsInventoryListACE,
	}
	inventoryAttributesACE = inventoryACE{
		mask:        windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE,
		inheritance: windows.NO_INHERITANCE,
		present:     daclContainsInventoryAttributesACE,
	}
	inventorySelfACE = inventoryACE{
		mask: inventorySelfMask, inheritance: windows.NO_INHERITANCE, files: true,
		present: daclContainsInventorySelfACE,
	}
)

// ensureInventoryReadACE adds an ACE granting Read+Execute+Traverse on `path`
// to `sid`, inheriting to sub-containers and objects. If `path` doesn't exist
// or isn't a directory, silently succeed — the user may not have started the
// corresponding CLI yet; the next tick retries.
func ensureInventoryReadACE(path string, sid *windows.SID) (inventoryDACLResult, error) {
	return ensureInventoryACE(path, sid, inventoryReadACE)
}

// inventoryListMask lets the service list a folder and read its own
// attributes, and nothing below it.
const inventoryListMask = windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE

// ensureInventoryListACE grants `sid` inventoryListMask on `path` alone
// (inventoryDACLListOnlyDirs).
func ensureInventoryListACE(path string, sid *windows.SID) (inventoryDACLResult, error) {
	return ensureInventoryACE(path, sid, inventoryListACE)
}

// inventorySelfMask lets the service read one folder's own listing or one
// file's content, as Go's os.Open asks (GENERIC_READ), and nothing below.
const inventorySelfMask = windows.FILE_GENERIC_READ

// ensureInventorySelfACE grants `sid` inventorySelfMask on the folder or
// regular file `path` alone (the profile-root .claude.json of GAP-1204).
func ensureInventorySelfACE(path string, sid *windows.SID) (inventoryDACLResult, error) {
	return ensureInventoryACE(path, sid, inventorySelfACE)
}

func ensureInventoryACE(path string, sid *windows.SID, kind inventoryACE) (inventoryDACLResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return inventoryDACLSkippedMissing, nil
		}
		return inventoryDACLSkippedMissing, fmt.Errorf("stat: %w", err)
	}
	if !fi.IsDir() && !(kind.files && fi.Mode().IsRegular()) {
		return inventoryDACLSkippedMissing, nil
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("extend: %w", err)
	}
	sd, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("get DACL: %w", err)
	}
	existing, _, err := sd.DACL()
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("inspect DACL: %w", err)
	}
	// Refuse to touch a directory that has no explicit DACL. `existing == nil`
	// after a successful `sd.DACL()` means the descriptor carries a null DACL
	// (everyone-allowed semantics, not a missing-info error). Passing that
	// through `ACLFromEntries(entries, nil)` would build an ACL containing
	// only our gateway grant and `SetNamedSecurityInfo` would replace the
	// null DACL with a DACL granting exclusively the gateway service SID —
	// silently stripping access from every other principal. Skip and surface
	// the anomaly via the failed counter so an operator can investigate the
	// unusual permission state.
	if existing == nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("null DACL on %s; refusing to replace with sole gateway-service ACE", path)
	}
	if kind.present(existing, sid) {
		return inventoryDACLAlreadyPresent, nil
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: kind.mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       kind.inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, existing)
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("merge ACE: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, merged, nil,
	); err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("set DACL: %w", err)
	}
	return inventoryDACLGranted, nil
}

// ensureInventoryACEPinned reads and updates one pinned object. The preceding
// path walk is advisory; the handle and final-path check enforce the boundary
// if a user changes a directory while the enumerator is running.
func ensureInventoryACEPinned(home, rel string, sid *windows.SID, kind inventoryACE) (inventoryDACLResult, error) {
	handle, err := openInventoryDACLHandle(home, rel)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return inventoryDACLSkippedMissing, nil
	}
	if err != nil {
		return inventoryDACLSkippedMissing, err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return inventoryDACLSkippedMissing, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 &&
		!(kind.files && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0) {
		return inventoryDACLSkippedMissing, nil
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("get DACL: %w", err)
	}
	existing, _, err := sd.DACL()
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("inspect DACL: %w", err)
	}
	if existing == nil {
		return inventoryDACLSkippedMissing, errors.New("null DACL; refusing to replace with sole gateway-service ACE")
	}
	if kind.present(existing, sid) {
		return inventoryDACLAlreadyPresent, nil
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: kind.mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       kind.inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, existing)
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("merge ACE: %w", err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, merged, nil); err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("set DACL: %w", err)
	}
	return inventoryDACLGranted, nil
}

func revokeInventoryLegacyReadACEPinned(home, rel string, sid *windows.SID) (inventoryDACLResult, error) {
	handle, err := openInventoryDACLHandle(home, rel)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return inventoryDACLSkippedMissing, nil
	}
	if err != nil {
		return inventoryDACLSkippedMissing, err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return inventoryDACLSkippedMissing, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return inventoryDACLSkippedMissing, nil
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return inventoryDACLSkippedMissing, err
	}
	existing, _, err := sd.DACL()
	if err != nil || existing == nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("inspect legacy IDE DACL: %v", err)
	}
	if !daclContainsInventoryReadACE(existing, sid) {
		return inventoryDACLSkippedMissing, nil
	}
	for i := uint16(0); i < existing.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(existing, uint32(i), &ace); err != nil {
			return inventoryDACLSkippedMissing, err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE &&
			(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return inventoryDACLSkippedMissing, errors.New("service SID has an explicit deny on legacy IDE path")
		}
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessMode: windows.REVOKE_ACCESS,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}
	narrowed, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, existing)
	if err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("remove legacy IDE grant: %w", err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, narrowed, nil); err != nil {
		return inventoryDACLSkippedMissing, fmt.Errorf("set narrow IDE DACL: %w", err)
	}
	return inventoryDACLGranted, nil
}

// daclContainsInventoryReadACE reports whether `acl` already grants `sid`
// at least Read+Execute on the folder itself and, inherited, on everything
// below it. Used as an idempotency short-circuit so repeat ticks skip the
// (get, merge, set) round-trip, which rewrites the inherited ACEs of every
// object under the folder.
//
// Windows stores the grant ensureInventoryReadACE writes as two ACEs: one
// with the generic rights mapped to file rights for the folder, and an
// INHERIT_ONLY_ACE with the generic rights for its children. Both shapes,
// and a single ACE that covers both, count (GAP-1863: matching only the
// unsplit generic shape re-granted every folder on every pass). An ACE
// with NO_PROPAGATE_INHERIT_ACE does not cover the children.
func daclContainsInventoryReadACE(acl *windows.ACL, sid *windows.SID) bool {
	if acl == nil || sid == nil {
		return false
	}
	want := mapWindowsUserPathGenericMask(windows.GENERIC_READ | windows.GENERIC_EXECUTE)
	const inherit = uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	self, children := false, false
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID == nil || !windows.EqualSid(aceSID, sid) {
			continue
		}
		if mapWindowsUserPathGenericMask(ace.Mask)&want != want {
			continue
		}
		flags := ace.Header.AceFlags
		if flags&windows.INHERIT_ONLY_ACE == 0 {
			self = true
		}
		if flags&inherit == inherit && flags&windows.NO_PROPAGATE_INHERIT_ACE == 0 {
			children = true
		}
	}
	return self && children
}

// daclContainsInventoryListACE reports whether `acl` already grants `sid`
// inventoryListMask on the object itself.
func daclContainsInventoryListACE(acl *windows.ACL, sid *windows.SID) bool {
	if acl == nil || sid == nil {
		return false
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID != nil && windows.EqualSid(aceSID, sid) &&
			uint32(ace.Mask)&uint32(inventoryListMask) == uint32(inventoryListMask) {
			return true
		}
	}
	return false
}

func daclContainsInventoryAttributesACE(acl *windows.ACL, sid *windows.SID) bool {
	if acl == nil || sid == nil {
		return false
	}
	want := windows.ACCESS_MASK(windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID != nil && windows.EqualSid(aceSID, sid) && mapWindowsUserPathGenericMask(ace.Mask)&want == want {
			return true
		}
	}
	return false
}

// daclContainsInventorySelfACE reports whether `acl` already grants `sid`
// inventorySelfMask on the object itself, explicitly or inherited.
func daclContainsInventorySelfACE(acl *windows.ACL, sid *windows.SID) bool {
	if acl == nil || sid == nil {
		return false
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID != nil && windows.EqualSid(aceSID, sid) &&
			mapWindowsUserPathGenericMask(ace.Mask)&inventorySelfMask == inventorySelfMask {
			return true
		}
	}
	return false
}

// sanitizeInventoryDACLError maps `err` to a short category label
// safe to write into the enumeration log line. The Windows syscall
// errors wrapped inside `ensureInventoryReadACE` failures often
// stringify with the offending path (e.g. `stat` -> `os.PathError`,
// whose Error() includes the absolute `C:\Users\<name>\.claude` path
// verbatim). Emitting a category instead of the wrapped message
// preserves the diagnostic signal — "permission-denied" vs
// "not-found" vs other — without leaking the user's profile
// location to the stderr audit stream.
func sanitizeInventoryDACLError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, errInventoryDACLLink):
		return "reparse-point"
	case errors.Is(err, os.ErrNotExist):
		return "not-found"
	case errors.Is(err, os.ErrPermission):
		return "permission-denied"
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return "permission-denied"
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND),
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return "not-found"
	default:
		return "other"
	}
}

// discoverGatewayServiceName looks up the DefenseClaw gateway service via the
// Service Control Manager. Prefers a certification-scoped service if present;
// falls back to the production name. Returns an error if neither is installed.
func discoverGatewayServiceName() (string, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("connect SCM: %w", err)
	}
	defer manager.Disconnect()
	names, err := manager.ListServices()
	if err != nil {
		return "", fmt.Errorf("enumerate services: %w", err)
	}
	var certScoped string
	for _, n := range names {
		switch {
		case gatewayServiceNamePattern.MatchString(n):
			// Prefer the first certification-scoped match; the pattern
			// contract enforces exactly one per install.
			if certScoped == "" {
				certScoped = n
			}
		case n == productionGatewayServiceName:
			// Keep looking for a cert-scoped one; production is the fallback.
		}
	}
	if certScoped != "" {
		return certScoped, nil
	}
	for _, n := range names {
		if n == productionGatewayServiceName {
			return productionGatewayServiceName, nil
		}
	}
	return "", errors.New("no DefenseClaw gateway service installed")
}

// sidIsNTServiceInventory validates that `sid` names an NT SERVICE virtual
// account: SID authority is NT AUTHORITY (Value 5) with first sub-authority 80
// (SECURITY_SERVICE_ID_BASE_RID). Deliberately duplicated from the equivalent
// helper in internal/managed to avoid an enterprisehooks → managed import;
// contract is byte-identical and covered by the shared trust-model comment.
func sidIsNTServiceInventory(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	authority := sid.IdentifierAuthority()
	if authority.Value != [6]byte{0, 0, 0, 0, 0, 5} {
		return false
	}
	if sid.SubAuthorityCount() < 1 {
		return false
	}
	return sid.SubAuthority(0) == 80
}
