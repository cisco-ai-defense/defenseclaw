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
	windowsManagedRuntimeChildOpen = openWindowsManagedRuntimeChild
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
	runtimeDirectories, err := openWindowsManagedRuntimeDirectories(home, targetSID)
	if err != nil {
		return InstallResult{}, err
	}
	defer runtimeDirectories.close()
	runtimePaths := windowsClaudeRuntimePaths(setupOpts, conn)
	runtimeSnapshot, err := snapshotWindowsRuntimeFiles(runtimePaths)
	if err != nil {
		_ = runtimeDirectories.rollback()
		return InstallResult{}, err
	}
	rollbackRuntime := func(cause error) error {
		if restoreErr := restoreWindowsRuntimeFiles(runtimeSnapshot); restoreErr != nil {
			cause = fmt.Errorf("%v (runtime rollback failed: %v)", cause, restoreErr)
		}
		if restoreErr := runtimeDirectories.rollback(); restoreErr != nil {
			cause = fmt.Errorf("%v (runtime security rollback failed: %v)", cause, restoreErr)
		}
		return cause
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
	if err := hardenWindowsManagedRuntimeFiles(runtimePaths, targetSID); err != nil {
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
	if err := winpath.RejectReparseChain(path); err != nil {
		return fmt.Errorf("enterprise hooks: %w", err)
	}
	return nil
}

func windowsSIDString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}

type windowsManagedRuntimeDirectory struct {
	file       *os.File
	parent     *os.File
	name       string
	created    bool
	identity   windows.ByHandleFileInformation
	descriptor *windows.SECURITY_DESCRIPTOR
}

type windowsManagedRuntimeDirectories struct {
	home     *os.File
	children [2]windowsManagedRuntimeDirectory
	closed   bool
}

func openWindowsManagedRuntimeDirectories(home string, target *windows.SID) (*windowsManagedRuntimeDirectories, error) {
	homePtr, err := winpath.UTF16Ptr(home)
	if err != nil {
		return nil, err
	}
	homeHandle, err := windows.CreateFile(
		homePtr,
		windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: bind target user home: %w", err)
	}
	directories := &windowsManagedRuntimeDirectories{home: os.NewFile(uintptr(homeHandle), home)}
	if directories.home == nil {
		_ = windows.CloseHandle(homeHandle)
		return nil, fmt.Errorf("enterprise hooks: bind target user home")
	}
	if _, _, err := validateWindowsRuntimeDirectoryHandle(directories.home, home, target, true); err != nil {
		directories.close()
		return nil, fmt.Errorf("enterprise hooks: bound user home trust check failed: %w", err)
	}
	parent := directories.home
	for index, name := range []string{".defenseclaw", "hooks"} {
		directories.children[index], err = windowsManagedRuntimeChildOpen(parent, name, target)
		if err != nil {
			_ = directories.rollback()
			return nil, fmt.Errorf("enterprise hooks: bind per-user %s directory: %w", name, err)
		}
		parent = directories.children[index].file
	}
	return directories, nil
}

func openWindowsManagedRuntimeChild(parent *os.File, name string, target *windows.SID) (windowsManagedRuntimeDirectory, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return windowsManagedRuntimeDirectory{}, fmt.Errorf("invalid runtime directory name %q", name)
	}
	descriptor, err := windowsManagedRuntimeSecurityDescriptor(target, true)
	if err != nil {
		return windowsManagedRuntimeDirectory{}, err
	}
	attributes, err := windowsManagedRuntimeObjectAttributes(parent, name, descriptor)
	if err != nil {
		return windowsManagedRuntimeDirectory{}, err
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|
			windows.WRITE_DAC|windows.WRITE_OWNER|windows.SYNCHRONIZE,
		attributes, &status, nil, windows.FILE_ATTRIBUTE_DIRECTORY, windows.FILE_SHARE_READ,
		windows.FILE_OPEN_IF,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0,
	)
	if err != nil {
		if errors.Is(err, windows.STATUS_REPARSE_POINT_ENCOUNTERED) {
			return windowsManagedRuntimeDirectory{}, fmt.Errorf("reparse point substituted for %s", name)
		}
		return windowsManagedRuntimeDirectory{}, err
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return windowsManagedRuntimeDirectory{}, fmt.Errorf("wrap runtime directory handle %s", name)
	}
	directory := windowsManagedRuntimeDirectory{file: file, parent: parent, name: name, created: status.Information == 2}
	directory.descriptor, directory.identity, err = validateWindowsRuntimeDirectoryHandle(file, name, target, false)
	if err == nil {
		err = setWindowsManagedRuntimeHandleProtection(file, target, true)
	}
	if err != nil {
		_ = directory.rollback()
		return windowsManagedRuntimeDirectory{}, err
	}
	held, err := openWindowsManagedRuntimeDirectoryByIdentity(
		parent, name, directory.identity,
		windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
	)
	if err != nil {
		_ = directory.rollback()
		return windowsManagedRuntimeDirectory{}, err
	}
	if err := file.Close(); err != nil {
		held.Close()
		return windowsManagedRuntimeDirectory{}, err
	}
	directory.file = held
	return directory, nil
}

func windowsManagedRuntimeObjectAttributes(parent *os.File, name string, descriptor *windows.SECURITY_DESCRIPTOR) (*windows.OBJECT_ATTRIBUTES, error) {
	unicode, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	return &windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      windows.Handle(parent.Fd()),
		ObjectName:         unicode,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: descriptor,
	}, nil
}

func validateWindowsRuntimeDirectoryHandle(file *os.File, label string, target *windows.SID, requireTargetOwner bool) (*windows.SECURITY_DESCRIPTOR, windows.ByHandleFileInformation, error) {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, info, fmt.Errorf("symlinks, junctions, and reparse points are not allowed: %s", label)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return nil, info, fmt.Errorf("expected directory: %s", label)
	}
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return nil, info, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return nil, info, err
	}
	if requireTargetOwner && (owner == nil || !owner.Equals(target)) {
		return nil, info, fmt.Errorf("owner SID %s does not match target SID %s on %s", windowsSIDString(owner), windowsSIDString(target), label)
	}
	if !requireTargetOwner && (owner == nil || (!owner.Equals(target) && !windowsEnterpriseRuntimeAdminIdentity(owner))) {
		return nil, info, fmt.Errorf("foreign owner SID %s on %s", windowsSIDString(owner), label)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return nil, info, fmt.Errorf("null or unreadable Windows DACL on %s", label)
	}
	if err := rejectWindowsRuntimeWriteACEs(label, dacl, target, true, true, true); err != nil {
		return nil, info, err
	}
	return descriptor, info, nil
}

func (directory *windowsManagedRuntimeDirectory) rollback() error {
	if directory.file == nil {
		return nil
	}
	err := directory.file.Close()
	directory.file = nil
	if err != nil {
		return err
	}
	file, err := openWindowsManagedRuntimeDirectoryByIdentity(
		directory.parent, directory.name, directory.identity,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ,
	)
	if err != nil {
		return err
	}
	defer file.Close()
	if directory.created {
		deleteFile := uint32(1)
		return windows.SetFileInformationByHandle(
			windows.Handle(file.Fd()), windows.FileDispositionInfo,
			(*byte)(unsafe.Pointer(&deleteFile)), uint32(unsafe.Sizeof(deleteFile)),
		)
	}
	return restoreWindowsSecurityDescriptorHandle(file, directory.descriptor)
}

func openWindowsManagedRuntimeDirectoryByIdentity(
	parent *os.File, name string, identity windows.ByHandleFileInformation, access, share uint32,
) (*os.File, error) {
	attributes, err := windowsManagedRuntimeObjectAttributes(parent, name, nil)
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle, access, attributes, &status, nil, 0, share,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0,
	)
	if err != nil {
		return nil, err
	}
	var current windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &current); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	if current.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		current.VolumeSerialNumber != identity.VolumeSerialNumber ||
		current.FileIndexHigh != identity.FileIndexHigh || current.FileIndexLow != identity.FileIndexLow {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("runtime directory identity changed while held: %s", name)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap held runtime directory handle: %s", name)
	}
	return file, nil
}

func (directories *windowsManagedRuntimeDirectories) rollback() error {
	if directories == nil || directories.closed {
		return nil
	}
	var failures []error
	for index := len(directories.children) - 1; index >= 0; index-- {
		if err := directories.children[index].rollback(); err != nil {
			failures = append(failures, err)
		}
	}
	directories.close()
	return errors.Join(failures...)
}

func (directories *windowsManagedRuntimeDirectories) close() {
	if directories == nil || directories.closed {
		return
	}
	for index := len(directories.children) - 1; index >= 0; index-- {
		if directories.children[index].file != nil {
			_ = directories.children[index].file.Close()
		}
	}
	if directories.home != nil {
		_ = directories.home.Close()
	}
	directories.closed = true
}

type windowsRuntimeFileSnapshot struct {
	path     string
	existed  bool
	data     []byte
	security *windows.SECURITY_DESCRIPTOR
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
		snapshot.security, err = windows.GetNamedSecurityInfo(
			path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
		)
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks: snapshot runtime security %s: %w", path, err)
		}
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
			} else if err := restoreWindowsSecurityDescriptor(snapshot.path, snapshot.security); err != nil {
				failures = append(failures, fmt.Sprintf("%s security: %v", snapshot.path, err))
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

func restoreWindowsSecurityDescriptor(path string, descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil {
		return nil
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	securityInfo := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		securityInfo |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		securityInfo |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, securityInfo, owner, nil, dacl, nil)
}

func restoreWindowsSecurityDescriptorHandle(file *os.File, descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil {
		return nil
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	securityInfo := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		securityInfo |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		securityInfo |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, securityInfo, owner, nil, dacl, nil)
}

func hardenWindowsManagedRuntime(dataDir string, paths []string, target *windows.SID) error {
	if err := setWindowsManagedRuntimeProtection(dataDir, target, true); err != nil {
		return fmt.Errorf("enterprise hooks: harden administrator-managed data directory: %w", err)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := setWindowsManagedRuntimeProtection(hookDir, target, true); err != nil {
		return fmt.Errorf("enterprise hooks: harden administrator-managed hook directory: %w", err)
	}
	return hardenWindowsManagedRuntimeFiles(paths, target)
}

func hardenWindowsManagedRuntimeFiles(paths []string, target *windows.SID) error {
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
	owner, acl, err := windowsManagedRuntimeProtection(target, directory)
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

func setWindowsManagedRuntimeHandleProtection(file *os.File, target *windows.SID, directory bool) error {
	owner, acl, err := windowsManagedRuntimeProtection(target, directory)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, acl, nil,
	)
}

func windowsManagedRuntimeSecurityDescriptor(target *windows.SID, directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	owner, acl, err := windowsManagedRuntimeProtection(target, directory)
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := descriptor.SetOwner(owner, false); err != nil {
		return nil, err
	}
	if err := descriptor.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	return descriptor, nil
}

func windowsManagedRuntimeProtection(target *windows.SID, directory bool) (*windows.SID, *windows.ACL, error) {
	owner, err := windowsManagedRuntimeOwnerSID()
	if err != nil {
		return nil, nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}
	return owner, acl, nil
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
