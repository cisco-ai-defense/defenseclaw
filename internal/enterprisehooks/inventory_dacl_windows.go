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

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// inventoryDACLDotdirs enumerates the top-level user-profile subdirectories the
// AI discovery scanner walks for skill, plugin, rule, and MCP-config signatures.
// Kept in sync with the catalog under internal/inventory/ai_signatures.json —
// this list covers the ancestor traversal that the scanner needs. Child ACEs
// inherit from these parents via SUB_CONTAINERS_AND_OBJECTS_INHERIT so
// per-file reads don't need a separate grant.
var inventoryDACLDotdirs = []string{
	".claude",
	".codex",
	".cursor",
	".gemini",
	".openhands",
	".openclaw",
	".hermes",
	".windsurf",
	".codeium",
	".amp",
	".opencode",
	".agents",
	".config",
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
		for _, dotdir := range inventoryDACLDotdirs {
			path := filepath.Join(home, dotdir)
			result, err := ensureInventoryReadACE(path, sid)
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
	if daclContainsInventoryReadACE(existing, sid) {
		return inventoryDACLAlreadyPresent, nil
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_READ | windows.GENERIC_EXECUTE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
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

// daclContainsInventoryReadACE reports whether `acl` already contains an
// allow-access ACE granting `sid` at least Read+Execute with the same
// inheritance semantics we would install. Used as an idempotency short-circuit
// so repeat ticks skip the (get, merge, set) round-trip when the ACE is
// already present in the exact shape we need.
//
// Inheritance requirements match the `SUB_CONTAINERS_AND_OBJECTS_INHERIT` flag
// set we pass to `ACLFromEntries`: both OBJECT_INHERIT_ACE (files) and
// CONTAINER_INHERIT_ACE (subdirs) must be present, and neither
// NO_PROPAGATE_INHERIT_ACE nor INHERIT_ONLY_ACE may be set — an ACE that
// grants the parent but does not propagate to children is NOT equivalent for
// our purposes (the scanner reads files INSIDE the dotdirs, not the dotdir
// itself), and an INHERIT_ONLY_ACE that doesn't apply to the parent leaves
// the traversal grant absent. Rebuilding the ACL is preferable to leaving a
// half-configured ACE in place.
func daclContainsInventoryReadACE(acl *windows.ACL, sid *windows.SID) bool {
	if acl == nil || sid == nil {
		return false
	}
	const wantMask = uint32(windows.GENERIC_READ | windows.GENERIC_EXECUTE)
	const requiredInherit = uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	const forbiddenInherit = uint8(windows.NO_PROPAGATE_INHERIT_ACE | windows.INHERIT_ONLY_ACE)
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
		if uint32(ace.Mask)&wantMask != wantMask {
			continue
		}
		flags := ace.Header.AceFlags
		if flags&requiredInherit != requiredInherit {
			continue
		}
		if flags&forbiddenInherit != 0 {
			continue
		}
		return true
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
