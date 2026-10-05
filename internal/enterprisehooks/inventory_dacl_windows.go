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

	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// inventoryDACLDotdirs enumerates the top-level user-profile subdirectories the
// AI discovery scanner walks for skill, plugin, rule, and MCP-config signatures,
// and the IDE folders the IDE plugin inventory reads (ideplugins.WindowsHomeDirs;
// without them a managed host listed no IDE plugin for anyone, GAP-0042).
// Kept in sync with the catalog under internal/inventory/ai_signatures.json —
// this list covers the ancestor traversal that the scanner needs. Child ACEs
// inherit from these parents via SUB_CONTAINERS_AND_OBJECTS_INHERIT so
// per-file reads don't need a separate grant.
var inventoryDACLDotdirs = append(append([]string{
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
}, legacyconnector.InventoryDotDirs...), ideplugins.WindowsHomeDirs()...)

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
// If gatewayServiceName is empty, discovers it via SCM enumeration (matches
// the cert-scoped or production naming). Returns an error only if the pass
// cannot even begin (SCM unavailable, service SID resolution fails); per-path
// failures are logged and swallowed.
func GrantGatewayInventoryReadForManifest(manifest Manifest, gatewayServiceName string, logf EnumerationLogger) error {
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
		type grant struct {
			dir    string
			ensure func(string, *windows.SID) (inventoryDACLResult, error)
		}
		grants := make([]grant, 0, len(inventoryDACLDotdirs)+len(inventoryDACLListOnlyDirs))
		for _, dotdir := range inventoryDACLDotdirs {
			if _, owned := guardianOwned[key][dotdir]; !owned {
				grants = append(grants, grant{dotdir, ensureInventoryReadACE})
			}
		}
		for _, dir := range inventoryDACLListOnlyDirs {
			grants = append(grants, grant{dir, ensureInventoryListACE})
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

type inventoryDACLResult int

const (
	inventoryDACLSkippedMissing inventoryDACLResult = iota
	inventoryDACLGranted
	inventoryDACLAlreadyPresent
)

// ensureInventoryReadACE adds an ACE granting Read+Execute+Traverse on `path`
// to `sid`, inheriting to sub-containers and objects. If `path` doesn't exist
// or isn't a directory, silently succeed — the user may not have started the
// corresponding CLI yet; the next tick retries.
func ensureInventoryReadACE(path string, sid *windows.SID) (inventoryDACLResult, error) {
	return ensureInventoryACE(path, sid, windows.GENERIC_READ|windows.GENERIC_EXECUTE, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

// inventoryListMask lets the service list a folder and read its own
// attributes, and nothing below it.
const inventoryListMask = windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE

// ensureInventoryListACE grants `sid` inventoryListMask on `path` alone
// (inventoryDACLListOnlyDirs).
func ensureInventoryListACE(path string, sid *windows.SID) (inventoryDACLResult, error) {
	return ensureInventoryACE(path, sid, inventoryListMask, windows.NO_INHERITANCE)
}

func ensureInventoryACE(path string, sid *windows.SID, mask windows.ACCESS_MASK, inheritance uint32) (inventoryDACLResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return inventoryDACLSkippedMissing, nil
		}
		return inventoryDACLSkippedMissing, fmt.Errorf("stat: %w", err)
	}
	if !fi.IsDir() {
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
	present := daclContainsInventoryReadACE(existing, sid)
	if inheritance == windows.NO_INHERITANCE {
		present = daclContainsInventoryListACE(existing, sid)
	}
	if present {
		return inventoryDACLAlreadyPresent, nil
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
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
