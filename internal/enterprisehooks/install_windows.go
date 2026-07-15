//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	windowsEnterpriseAdministratorCheck = requireWindowsEnterpriseAdministrator
	windowsEnterpriseHookExecutable     = defaultWindowsEnterpriseHookExecutable
	windowsEnterpriseHookTrustCheck     = func(path string) error {
		return managed.ValidateTrustedFilePath(path, "enterprise hook executable")
	}
	windowsManagedRuntimeOwnerSID = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	}
)

func platformInstall(ctx context.Context, opts InstallOptions) (InstallResult, bool, error) {
	result, err := installWindowsClaudeManagedResult(ctx, opts)
	return result, true, err
}

func installWindowsClaudeManagedResult(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector is required")
	}
	if name != "claudecode" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: native Windows managed policy currently supports only claudecode, got %q", name)
	}
	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	conn, ok := reg.Get(name)
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	provider, ok := conn.(connector.ManagedHookPolicyProvider)
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q does not expose a managed policy contract", name)
	}

	home, targetSID, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return InstallResult{}, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return InstallResult{}, err
	}
	if err := validateWindowsUserPathPrefix(home, dataDir, targetSID, true); err != nil {
		return InstallResult{}, err
	}

	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return InstallResult{}, err
	}
	if !filepath.IsAbs(hookExecutable) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: managed hook executable is not absolute: %s", hookExecutable)
	}
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: managed hook executable trust check failed: %w", err)
	}

	setupOpts := connector.SetupOpts{
		DataDir:            dataDir,
		ProxyAddr:          strings.TrimSpace(opts.ProxyAddr),
		APIAddr:            strings.TrimSpace(opts.APIAddr),
		APIToken:           strings.TrimSpace(opts.APIToken),
		HookAPIToken:       strings.TrimSpace(opts.APIToken),
		HookAPITokenScoped: true,
		OTLPPathToken:      strings.TrimSpace(opts.OTLPPathToken),
		Interactive:        false,
		ManagedEnterprise:  true,
		WorkspaceDir:       strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:       strings.TrimSpace(opts.HookFailMode),
		HILTEnabled:        opts.HILTEnabled,
		AgentVersion:       strings.TrimSpace(opts.AgentVersion),
		HookContractID:     strings.TrimSpace(opts.HookContractID),
		HookExecutable:     filepath.Clean(hookExecutable),
	}
	if setupOpts.APIAddr == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: API address is required")
	}
	if setupOpts.HookAPIToken == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector-scoped hook token is required")
	}
	if setupOpts.AgentVersion == "" {
		setupOpts.AgentVersion = connector.LoadCachedAgentVersion(dataDir, conn.Name())
	}
	if setupOpts.HookContractID == "" {
		resolution := connector.ResolveHookContract(conn.Name(), setupOpts.AgentVersion)
		setupOpts.HookContractID = resolution.Contract.ContractID
	}
	if err := validateHookContract(opts.GuardrailMode, conn, setupOpts); err != nil {
		return InstallResult{}, err
	}

	policyBody, err := provider.ManagedHookPolicy(setupOpts)
	if err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: build Claude Code managed policy: %w", err)
	}
	if err := provider.VerifyManagedHookPolicy(policyBody, setupOpts); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: verify rendered Claude Code managed policy: %w", err)
	}

	hookDir := filepath.Join(dataDir, "hooks")
	runtimePaths := windowsClaudeRuntimePaths(setupOpts, conn)
	runtimeSnapshot, err := snapshotWindowsRuntimeFiles(runtimePaths)
	if err != nil {
		return InstallResult{}, err
	}
	createdDataDir := false
	if _, statErr := os.Lstat(dataDir); errors.Is(statErr, os.ErrNotExist) {
		createdDataDir = true
	}
	createdHookDir := false
	if _, statErr := os.Lstat(hookDir); errors.Is(statErr, os.ErrNotExist) {
		createdHookDir = true
	}
	rollbackRuntime := func(cause error) error {
		if restoreErr := restoreWindowsRuntimeFiles(runtimeSnapshot); restoreErr != nil {
			return fmt.Errorf("%v (runtime rollback failed: %v)", cause, restoreErr)
		}
		if createdDataDir || createdHookDir {
			_ = removeEmptyWindowsDirectory(hookDir)
		}
		if createdDataDir {
			_ = removeEmptyWindowsDirectory(dataDir)
		} else if hardenErr := hardenWindowsManagedRuntime(dataDir, runtimePaths, targetSID); hardenErr != nil {
			return fmt.Errorf("%v (runtime rollback hardening failed: %v)", cause, hardenErr)
		}
		return cause
	}

	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: create per-user hook runtime: %w", err)
	}
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, setupOpts, conn); err != nil {
		return InstallResult{}, rollbackRuntime(fmt.Errorf("enterprise hooks: write managed Claude Code hook runtime: %w", err))
	}
	policyPath, rollbackPolicy, err := installWindowsClaudeManagedPolicy(policyBody, setupOpts, targetSID)
	if err != nil {
		return InstallResult{}, rollbackRuntime(err)
	}
	rollbackAll := func(cause error) error {
		if policyErr := rollbackPolicy(); policyErr != nil {
			cause = fmt.Errorf("%v (managed policy rollback failed: %v)", cause, policyErr)
		}
		return rollbackRuntime(cause)
	}

	lockEntry := connector.NewHookContractLockEntry(setupOpts, conn, version.Current().BinaryVersion)
	if err := connector.SaveHookContractLockEntry(dataDir, lockEntry); err != nil {
		return InstallResult{}, rollbackAll(fmt.Errorf("enterprise hooks: save hook contract lock: %w", err))
	}
	if err := hardenWindowsManagedRuntime(dataDir, runtimePaths, targetSID); err != nil {
		return InstallResult{}, rollbackAll(err)
	}
	persistedPolicy, err := os.ReadFile(policyPath)
	if err != nil {
		return InstallResult{}, rollbackAll(fmt.Errorf("enterprise hooks: read persisted Claude Code managed policy: %w", err))
	}
	if err := provider.VerifyManagedHookPolicy(persistedPolicy, setupOpts); err != nil {
		return InstallResult{}, rollbackAll(fmt.Errorf("enterprise hooks: persisted Claude Code managed policy is inactive: %w", err))
	}
	if err := verifyWindowsManagedRuntime(dataDir, runtimePaths, targetSID); err != nil {
		return InstallResult{}, rollbackAll(err)
	}
	if err := verifyWindowsClaudeManagedPolicy(policyPath, policyBody); err != nil {
		return InstallResult{}, rollbackAll(err)
	}
	_ = ctx // reserved for future bounded live-client verification
	hookScripts := []string{}
	if scriptProvider, ok := conn.(connector.HookScriptProvider); ok {
		hookScripts = scriptProvider.HookScripts(setupOpts)
	}
	return InstallResult{
		Connector:       conn.Name(),
		UserHome:        home,
		DataDir:         dataDir,
		HookConfigPaths: []string{policyPath},
		HookScripts:     sortedUnique(hookScripts),
		CreatedDirs:     sortedUnique([]string{dataDir, hookDir}),
		AgentVersion:    setupOpts.AgentVersion,
		HookContractID:  lockEntry.ContractID,
	}, nil
}

func platformWatchDirs(opts InstallOptions) ([]string, bool, error) {
	if strings.ToLower(strings.TrimSpace(opts.ConnectorName)) != "claudecode" {
		return nil, true, fmt.Errorf("enterprise hooks: native Windows managed policy currently supports only claudecode")
	}
	home, sid, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return nil, true, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return nil, true, err
	}
	if err := validateWindowsUserPathPrefix(home, dataDir, sid, true); err != nil {
		return nil, true, err
	}
	policyPath, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return nil, true, err
	}
	return sortedUnique([]string{dataDir, filepath.Join(dataDir, "hooks"), filepath.Dir(policyPath)}), true, nil
}

func platformRemoveManagedPolicy(_ context.Context, opts InstallOptions) error {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(opts.ConnectorName)) != "claudecode" {
		return fmt.Errorf("enterprise hooks: native Windows managed policy removal currently supports only claudecode")
	}
	var targetSID *windows.SID
	var home string
	var err error
	if strings.TrimSpace(opts.UserHome) != "" {
		home, targetSID, err = validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
		if err == nil {
			_, err = resolveWindowsEnterpriseDataDir(home, opts.DataDir)
		}
	} else {
		if strings.TrimSpace(opts.DataDir) != "" {
			return fmt.Errorf("enterprise hooks: --data-dir cannot be used for SID-only native Windows managed policy removal")
		}
		targetSID, err = validateWindowsEnterpriseTargetSID(opts.OwnerSID)
	}
	if err != nil {
		return err
	}
	return removeWindowsClaudeManagedPolicyTarget(targetSID)
}

// resolveWindowsEnterpriseDataDir keeps the administrator-written policy and
// the standard-user hook process bound to the same per-user runtime identity.
// The managed hook resolves the current profile through the process token, so
// accepting an arbitrary path here would install files that the hook can never
// find (or would require trusting project-controlled environment at runtime).
func resolveWindowsEnterpriseDataDir(home, requested string) (string, error) {
	defaultDir := filepath.Join(filepath.Clean(home), ".defenseclaw")
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return defaultDir, nil
	}
	abs, err := filepath.Abs(requested)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	abs = filepath.Clean(abs)
	if !sameWindowsEnterprisePath(abs, defaultDir) {
		return "", fmt.Errorf("enterprise hooks: custom data directories are not supported for native Windows managed Claude hooks; --data-dir must be %s", defaultDir)
	}
	return defaultDir, nil
}

func requireWindowsEnterpriseAdministrator() error {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return fmt.Errorf("enterprise hooks: native Windows managed policy install requires an elevated administrator or LocalSystem token")
}

func defaultWindowsEnterpriseHookExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve gateway executable: %w", err)
	}
	path := filepath.Join(filepath.Dir(executable), "defenseclaw-hook.exe")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: inspect sibling native hook executable %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("enterprise hooks: native hook executable is not a regular file: %s", path)
	}
	return filepath.Clean(path), nil
}

func validateWindowsEnterpriseHome(raw, rawSID string) (string, *windows.SID, error) {
	home := strings.TrimSpace(raw)
	if home == "" {
		return "", nil, fmt.Errorf("enterprise hooks: user home is required")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", nil, fmt.Errorf("enterprise hooks: resolve user home: %w", err)
	}
	home = filepath.Clean(abs)
	info, err := os.Lstat(home)
	if err != nil {
		return "", nil, fmt.Errorf("enterprise hooks: inspect user home %s: %w", home, err)
	}
	if !info.IsDir() {
		return "", nil, fmt.Errorf("enterprise hooks: user home is not a directory: %s", home)
	}
	owner, err := windowsPathOwner(home)
	if err != nil {
		return "", nil, fmt.Errorf("enterprise hooks: inspect user home owner: %w", err)
	}
	target := owner
	if strings.TrimSpace(rawSID) != "" {
		target, err = windows.StringToSid(strings.TrimSpace(rawSID))
		if err != nil {
			return "", nil, fmt.Errorf("enterprise hooks: parse target user SID: %w", err)
		}
	}
	if target == nil || windowsEnterpriseSystemIdentity(target) {
		return "", nil, fmt.Errorf("enterprise hooks: refusing non-interactive target SID %s", windowsSIDString(target))
	}
	if owner == nil || !owner.Equals(target) {
		return "", nil, fmt.Errorf("enterprise hooks: user home %s owner SID %s does not match target SID %s", home, windowsSIDString(owner), windowsSIDString(target))
	}
	if err := validateWindowsUserPathElement(home, target, true, true, true); err != nil {
		return "", nil, fmt.Errorf("enterprise hooks: user home trust check failed: %w", err)
	}
	if err := rejectWindowsReparseChain(home); err != nil {
		return "", nil, err
	}
	return home, target, nil
}

func validateWindowsEnterpriseTargetSID(raw string) (*windows.SID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("enterprise hooks: target user SID is required when the user profile is unavailable")
	}
	sid, err := windows.StringToSid(raw)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: parse target user SID: %w", err)
	}
	if windowsEnterpriseSystemIdentity(sid) {
		return nil, fmt.Errorf("enterprise hooks: refusing non-interactive target SID %s", windowsSIDString(sid))
	}
	return sid, nil
}

func validateWindowsUserPathPrefix(home, path string, target *windows.SID, allowMissing bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	if !pathInside(home, abs) {
		return fmt.Errorf("enterprise hooks: refusing path outside user home: %s", abs)
	}
	rel, err := filepath.Rel(home, abs)
	if err != nil {
		return err
	}
	current := filepath.Clean(home)
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if _, err := os.Lstat(current); err != nil {
			if errors.Is(err, os.ErrNotExist) && allowMissing {
				return nil
			}
			return fmt.Errorf("enterprise hooks: inspect user path %s: %w", current, err)
		}
		if err := validateWindowsUserPathElement(current, target, true, true, false); err != nil {
			return err
		}
	}
	return nil
}

func validateWindowsUserPathElement(path string, target *windows.SID, wantDir, protectChildren, requireTargetOwner bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("enterprise hooks: symlinks, junctions, and reparse points are not allowed: %s", path)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("enterprise hooks: expected directory: %s", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("enterprise hooks: expected regular file: %s", path)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Windows security descriptor for %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if requireTargetOwner {
		if owner == nil || !owner.Equals(target) {
			return fmt.Errorf("enterprise hooks: owner SID %s does not match target SID %s on %s", windowsSIDString(owner), windowsSIDString(target), path)
		}
	} else if owner == nil || (!owner.Equals(target) && !windowsEnterpriseRuntimeAdminIdentity(owner)) {
		return fmt.Errorf("enterprise hooks: foreign owner SID %s on %s", windowsSIDString(owner), path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("enterprise hooks: null or unreadable Windows DACL on %s", path)
	}
	return rejectWindowsRuntimeWriteACEs(path, dacl, target, wantDir, protectChildren, true)
}

func validateWindowsManagedRuntimePathElement(path string, target *windows.SID, wantDir, protectChildren bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("enterprise hooks: symlinks, junctions, and reparse points are not allowed: %s", path)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("enterprise hooks: expected directory: %s", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("enterprise hooks: expected regular file: %s", path)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Windows security descriptor for %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	expectedOwner, err := windowsManagedRuntimeOwnerSID()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve managed runtime owner: %w", err)
	}
	if owner == nil || expectedOwner == nil || !owner.Equals(expectedOwner) {
		return fmt.Errorf("enterprise hooks: managed runtime owner SID %s does not match administrator SID %s on %s", windowsSIDString(owner), windowsSIDString(expectedOwner), path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("enterprise hooks: null or unreadable Windows DACL on %s", path)
	}
	// Native installs reject system/administrator SIDs as target users before
	// reaching this validator. Allowing equality here is only a test seam for
	// unprivileged Windows test processes that cannot assign Administrators as
	// an object owner; production target and runtime-owner SIDs are distinct.
	return rejectWindowsRuntimeWriteACEs(path, dacl, target, wantDir, protectChildren, target.Equals(expectedOwner))
}

func rejectWindowsRuntimeWriteACEs(path string, dacl *windows.ACL, target *windows.SID, wantDir, protectChildren, allowTargetWrite bool) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("enterprise hooks: inspect Windows ACE %d for %s: %w", index, path, err)
		}
		if ace == nil {
			continue
		}
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		inherits := ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0
		if inheritOnly && (!protectChildren || !wantDir || !inherits) {
			continue
		}
		if !windowsEnterpriseWriteLikeAccess(ace.Mask, protectChildren) {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case accessAllowedCompoundACEType, accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("enterprise hooks: unsupported Windows allow ACE type 0x%x on %s", ace.Header.AceType, path)
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) || (inheritOnly && sid.IsWellKnown(windows.WinCreatorOwnerSid)) {
			continue
		}
		if sid.Equals(target) {
			if allowTargetWrite {
				continue
			}
			return fmt.Errorf("enterprise hooks: target user SID %s has write-like access mask 0x%x on managed runtime %s", windowsSIDString(sid), uint32(ace.Mask), path)
		}
		if !windowsEnterpriseRuntimeAdminIdentity(sid) {
			return fmt.Errorf("enterprise hooks: untrusted Windows principal %s has write-like access mask 0x%x on %s", windowsSIDString(sid), uint32(ace.Mask), path)
		}
	}
	return nil
}

func windowsEnterpriseWriteLikeAccess(mask windows.ACCESS_MASK, protectChildren bool) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	unsafeMask := windows.ACCESS_MASK(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES)
	if protectChildren {
		unsafeMask |= fileDeleteChild
	}
	return mask&unsafeMask != 0
}

func windowsEnterpriseSystemIdentity(sid *windows.SID) bool {
	if sid == nil {
		return true
	}
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalServiceSid) || sid.IsWellKnown(windows.WinNetworkServiceSid)
}

func windowsEnterpriseAdminIdentity(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	return err == nil && sid.Equals(trustedInstaller)
}

func windowsEnterpriseRuntimeAdminIdentity(sid *windows.SID) bool {
	if windowsEnterpriseAdminIdentity(sid) {
		return true
	}
	owner, err := windowsManagedRuntimeOwnerSID()
	return err == nil && owner != nil && sid != nil && owner.Equals(sid)
}

func windowsPathOwner(path string) (*windows.SID, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

func rejectWindowsReparseChain(path string) error {
	current, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		ptr, err := winpath.UTF16Ptr(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(ptr)
		if err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("enterprise hooks: reparse point in path: %s", current)
		}
		if err != nil && err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_PATH_NOT_FOUND {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func windowsSIDString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}

type windowsRuntimeFileSnapshot struct {
	path    string
	existed bool
	data    []byte
}

func windowsClaudeRuntimePaths(opts connector.SetupOpts, conn connector.Connector) []string {
	hookDir := filepath.Join(opts.DataDir, "hooks")
	paths := []string{
		filepath.Join(hookDir, ".token"),
		filepath.Join(hookDir, ".hookcfg"),
		filepath.Join(hookDir, ".hookcfg.claudecode"),
		filepath.Join(hookDir, ".hookcfg.lock"),
		filepath.Join(hookDir, ".hook-claudecode.token"),
		filepath.Join(hookDir, "_hardening.sh"),
		filepath.Join(opts.DataDir, "hook_contract_lock.json"),
	}
	if provider, ok := conn.(connector.HookScriptProvider); ok {
		paths = append(paths, provider.HookScripts(opts)...)
	}
	return sortedUnique(paths)
}

func snapshotWindowsRuntimeFiles(paths []string) ([]windowsRuntimeFileSnapshot, error) {
	snapshots := make([]windowsRuntimeFileSnapshot, 0, len(paths))
	for _, path := range paths {
		snapshot := windowsRuntimeFileSnapshot{path: path}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks: snapshot runtime file %s: %w", path, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4<<20 {
			return nil, fmt.Errorf("enterprise hooks: refusing unsafe runtime file during snapshot: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		snapshot.existed = true
		snapshot.data = data
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func restoreWindowsRuntimeFiles(snapshots []windowsRuntimeFileSnapshot) error {
	var failures []string
	for _, snapshot := range snapshots {
		if snapshot.existed {
			err := os.MkdirAll(filepath.Dir(snapshot.path), 0o700)
			if err == nil {
				err = os.WriteFile(snapshot.path, snapshot.data, 0o600)
			}
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
			}
			continue
		}
		if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func hardenWindowsManagedRuntime(dataDir string, paths []string, target *windows.SID) error {
	if err := setWindowsManagedRuntimeProtection(dataDir, target, true); err != nil {
		return fmt.Errorf("enterprise hooks: harden administrator-managed data directory: %w", err)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := setWindowsManagedRuntimeProtection(hookDir, target, true); err != nil {
		return fmt.Errorf("enterprise hooks: harden administrator-managed hook directory: %w", err)
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := setWindowsManagedRuntimeProtection(path, target, false); err != nil {
			return fmt.Errorf("enterprise hooks: harden runtime file %s: %w", path, err)
		}
	}
	return nil
}

func setWindowsManagedRuntimeProtection(path string, target *windows.SID, directory bool) error {
	if err := rejectWindowsReparseChain(path); err != nil {
		return err
	}
	owner, err := windowsManagedRuntimeOwnerSID()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	for _, sid := range []*windows.SID{owner, system} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	targetPermissions := windows.ACCESS_MASK(windows.GENERIC_READ)
	if directory {
		targetPermissions |= windows.GENERIC_EXECUTE
	}
	entries = append(entries, windows.EXPLICIT_ACCESS{
		AccessPermissions: targetPermissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(target)},
	})
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func setWindowsUserPathProtection(path string, target *windows.SID, directory bool) error {
	if err := rejectWindowsReparseChain(path); err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	for _, sid := range []*windows.SID{target, system, administrators} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, target, nil, nil, nil); err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func verifyWindowsManagedRuntime(dataDir string, paths []string, target *windows.SID) error {
	for _, item := range []struct {
		path string
		dir  bool
	}{
		{dataDir, true},
		{filepath.Join(dataDir, "hooks"), true},
	} {
		if err := validateWindowsManagedRuntimePathElement(item.path, target, item.dir, item.dir); err != nil {
			return fmt.Errorf("enterprise hooks: runtime verification failed: %w", err)
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := validateWindowsManagedRuntimePathElement(path, target, false, false); err != nil {
			return fmt.Errorf("enterprise hooks: runtime verification failed: %w", err)
		}
	}
	return nil
}

func removeEmptyWindowsDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(entries) != 0 {
		return err
	}
	return os.Remove(path)
}
