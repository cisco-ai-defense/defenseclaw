//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	windowsClaudeManagedPolicyFile = "90-defenseclaw.json"
	windowsClaudeManagedStateFile  = ".defenseclaw-managed-hooks.state"
	windowsClaudeManagedStateLimit = 64 << 10
)

var (
	windowsClaudeManagedPolicyPathResolver = defaultWindowsClaudeManagedPolicyPath
	windowsClaudeHigherPolicyCheck         = defaultWindowsClaudeHigherPolicyCheck
	windowsManagedPolicyOwnerSID           = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	}
	windowsManagedPolicyDirTrustCheck = func(path string) error {
		return managed.ValidateTrustedRuntimeDir(path, "Claude Code managed policy directory")
	}
	windowsManagedPolicyFileTrustCheck = func(path string) error {
		return managed.ValidateTrustedFilePath(path, "Claude Code managed policy file")
	}
	windowsManagedPolicyWriter            = writeWindowsManagedFile
	windowsClaudeManagedPolicyTransaction = withWindowsClaudeManagedPolicyTransaction
	windowsEnterpriseProfilePathResolver  = func() (string, error) {
		return windows.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
	}
)

type windowsClaudeManagedPolicyState struct {
	SchemaVersion  int      `json:"schema_version"`
	PolicySHA256   string   `json:"policy_sha256"`
	HookExecutable string   `json:"hook_executable"`
	TargetSIDs     []string `json:"target_sids"`
}

type windowsManagedFileSnapshot struct {
	path    string
	existed bool
	data    []byte
}

// ResolveWindowsClaudeManagedHookRuntime validates the machine-managed hook
// registration for the current interactive SID and returns that user's
// protected DefenseClaw runtime. A valid registration that does not include
// the current SID returns registered=false so the shared machine policy can
// safely no-op for users outside the administrator's target allow-list.
func ResolveWindowsClaudeManagedHookRuntime(hookExecutable string) (dataDir string, registered bool, err error) {
	profile, profileErr := windowsEnterpriseProfilePathResolver()
	if profileErr != nil {
		return "", false, fmt.Errorf("enterprise hooks: resolve current Windows profile: %w", profileErr)
	}
	profile, profileErr = filepath.Abs(profile)
	if profileErr != nil {
		return "", false, fmt.Errorf("enterprise hooks: resolve current Windows profile path: %w", profileErr)
	}
	profile = filepath.Clean(profile)
	dataDir = filepath.Join(profile, ".defenseclaw")

	policyPath, policyErr := windowsClaudeManagedPolicyPath()
	if policyErr != nil {
		return dataDir, false, policyErr
	}
	statePath := filepath.Join(filepath.Dir(policyPath), windowsClaudeManagedStateFile)
	policySnapshot, policyErr := snapshotWindowsManagedFile(policyPath)
	if policyErr != nil {
		return dataDir, false, policyErr
	}
	stateSnapshot, stateErr := snapshotWindowsManagedFile(statePath)
	if stateErr != nil {
		return dataDir, false, stateErr
	}
	state, ownershipErr := validateExistingWindowsManagedPolicyOwnership(policySnapshot, stateSnapshot)
	if ownershipErr != nil {
		return dataDir, false, ownershipErr
	}
	if !policySnapshot.existed {
		return dataDir, false, nil
	}
	if !sameWindowsEnterprisePath(state.HookExecutable, hookExecutable) {
		return dataDir, false, fmt.Errorf("enterprise hooks: invoking hook executable %s does not match active managed policy executable %s", hookExecutable, state.HookExecutable)
	}

	tokenUser, tokenErr := windows.GetCurrentProcessToken().GetTokenUser()
	if tokenErr != nil {
		return dataDir, false, fmt.Errorf("enterprise hooks: resolve current Windows hook SID: %w", tokenErr)
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return dataDir, false, fmt.Errorf("enterprise hooks: current Windows hook token has no user SID")
	}
	currentSID := tokenUser.User.Sid
	for _, rawSID := range state.TargetSIDs {
		if strings.EqualFold(rawSID, currentSID.String()) {
			registered = true
			break
		}
	}
	if !registered {
		return dataDir, false, nil
	}
	if _, _, err := validateWindowsEnterpriseHome(profile, currentSID.String()); err != nil {
		return dataDir, false, err
	}
	hookDir := filepath.Join(dataDir, "hooks")
	for _, item := range []struct {
		path string
		dir  bool
	}{
		{dataDir, true},
		{hookDir, true},
		{filepath.Join(hookDir, ".hookcfg"), false},
		{filepath.Join(hookDir, ".hookcfg.claudecode"), false},
		{filepath.Join(hookDir, ".hook-claudecode.token"), false},
	} {
		if err := validateWindowsManagedRuntimePathElement(item.path, currentSID, item.dir, item.dir); err != nil {
			return dataDir, false, fmt.Errorf("enterprise hooks: current managed runtime trust check failed for %s: %w", item.path, err)
		}
	}
	return dataDir, true, nil
}

func sameWindowsEnterprisePath(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	return errA == nil && errB == nil && strings.EqualFold(filepath.Clean(absA), filepath.Clean(absB))
}

func windowsClaudeManagedPolicyPath() (string, error) {
	path, err := windowsClaudeManagedPolicyPathResolver()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("enterprise hooks: Claude Code managed policy path is not absolute: %s", path)
	}
	path = filepath.Clean(path)
	if !strings.EqualFold(filepath.Base(path), windowsClaudeManagedPolicyFile) || !strings.EqualFold(filepath.Base(filepath.Dir(path)), "managed-settings.d") {
		return "", fmt.Errorf("enterprise hooks: refusing noncanonical Claude Code managed policy path: %s", path)
	}
	return path, nil
}

func defaultWindowsClaudeManagedPolicyPath() (string, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve Program Files known folder: %w", err)
	}
	return filepath.Join(programFiles, "ClaudeCode", "managed-settings.d", windowsClaudeManagedPolicyFile), nil
}

func defaultWindowsClaudeHigherPolicyCheck() error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\ClaudeCode`, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Claude Code HKLM managed policy: %w", err)
	}
	defer key.Close()
	settings, _, err := key.GetStringValue("Settings")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: read Claude Code HKLM Settings policy: %w", err)
	}
	if strings.TrimSpace(settings) != "" {
		return fmt.Errorf("enterprise hooks: Claude Code HKLM Settings policy has higher precedence than file-based policy; deploy the DefenseClaw hook matrix through the existing MDM/GPO source")
	}
	return nil
}

func withWindowsClaudeManagedPolicyTransaction(fn func() error) error {
	name, err := windows.UTF16PtrFromString(`Global\Cisco.DefenseClaw.ClaudeManagedHooks`)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return fmt.Errorf("enterprise hooks: build managed policy transaction mutex security: %w", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	mutex, err := windows.CreateMutex(attributes, false, name)
	if err != nil {
		return fmt.Errorf("enterprise hooks: open managed policy transaction mutex: %w", err)
	}
	defer windows.CloseHandle(mutex)
	// Windows mutex ownership is bound to the calling OS thread. Keep this
	// goroutine pinned until ReleaseMutex so the Go scheduler cannot move it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	wait, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
	if err != nil || (wait != windows.WAIT_OBJECT_0 && wait != windows.WAIT_ABANDONED) {
		return fmt.Errorf("enterprise hooks: acquire managed policy transaction mutex: wait=0x%x err=%v", wait, err)
	}
	defer windows.ReleaseMutex(mutex)
	return fn()
}

func installWindowsClaudeManagedPolicy(body []byte, opts connector.SetupOpts, targetSID *windows.SID) (path string, rollback func() error, err error) {
	var unlockedRollback func() error
	var installedState []byte
	err = windowsClaudeManagedPolicyTransaction(func() error {
		var transactionErr error
		path, unlockedRollback, transactionErr = installWindowsClaudeManagedPolicyUnlocked(body, opts, targetSID)
		if transactionErr == nil {
			installedState, transactionErr = os.ReadFile(filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile))
			if transactionErr != nil && unlockedRollback != nil {
				if rollbackErr := unlockedRollback(); rollbackErr != nil {
					transactionErr = fmt.Errorf("%v (managed policy rollback failed: %v)", transactionErr, rollbackErr)
				}
			}
		}
		return transactionErr
	})
	if err == nil && unlockedRollback != nil {
		rollback = func() error {
			return windowsClaudeManagedPolicyTransaction(func() error {
				currentPolicy, policyErr := os.ReadFile(path)
				currentState, stateErr := os.ReadFile(filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile))
				if policyErr != nil || stateErr != nil || !bytes.Equal(currentPolicy, body) || !bytes.Equal(currentState, installedState) {
					return fmt.Errorf("enterprise hooks: refusing managed policy rollback after a concurrent policy change")
				}
				return unlockedRollback()
			})
		}
	}
	return path, rollback, err
}

func installWindowsClaudeManagedPolicyUnlocked(body []byte, opts connector.SetupOpts, targetSID *windows.SID) (string, func() error, error) {
	if len(body) > windowsClaudeManagedStateLimit {
		return "", nil, fmt.Errorf("enterprise hooks: Claude Code managed policy exceeds %d bytes", windowsClaudeManagedStateLimit)
	}
	if err := windowsClaudeHigherPolicyCheck(); err != nil {
		return "", nil, err
	}
	path, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return "", nil, err
	}
	if err := inspectWindowsClaudeFilePolicyCompatibility(path); err != nil {
		return "", nil, err
	}
	statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
	policySnapshot, err := snapshotWindowsManagedFile(path)
	if err != nil {
		return "", nil, err
	}
	stateSnapshot, err := snapshotWindowsManagedFile(statePath)
	if err != nil {
		return "", nil, err
	}
	existingState, err := validateExistingWindowsManagedPolicyOwnership(policySnapshot, stateSnapshot)
	if err != nil {
		return "", nil, err
	}
	policyDir := filepath.Dir(path)
	policyRoot := filepath.Dir(policyDir)
	createdPolicyDir := !windowsPathExists(policyDir)
	createdPolicyRoot := !windowsPathExists(policyRoot)
	removeCreatedDirs := func() {
		if createdPolicyDir {
			_ = os.Remove(policyDir)
		}
		if createdPolicyRoot {
			_ = os.Remove(policyRoot)
		}
	}
	targets := append([]string(nil), existingState.TargetSIDs...)
	targets = append(targets, targetSID.String())
	targets = sortedUnique(targets)
	state := windowsClaudeManagedPolicyState{
		SchemaVersion:  1,
		PolicySHA256:   windowsManagedPolicyDigest(body),
		HookExecutable: filepath.Clean(opts.HookExecutable),
		TargetSIDs:     targets,
	}
	stateBody, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "", nil, err
	}
	stateBody = append(stateBody, '\n')
	if len(stateBody) > windowsClaudeManagedStateLimit {
		return "", nil, fmt.Errorf("enterprise hooks: Claude Code managed policy state exceeds %d bytes", windowsClaudeManagedStateLimit)
	}
	if err := ensureWindowsManagedPolicyDirectory(policyDir); err != nil {
		removeCreatedDirs()
		return "", nil, err
	}

	rollback := func() error {
		var failures []string
		for _, snapshot := range []windowsManagedFileSnapshot{policySnapshot, stateSnapshot} {
			if err := restoreWindowsManagedFile(snapshot); err != nil {
				failures = append(failures, err.Error())
			}
		}
		removeCreatedDirs()
		if len(failures) > 0 {
			return fmt.Errorf("%s", strings.Join(failures, "; "))
		}
		return nil
	}
	if err := windowsManagedPolicyWriter(path, body, true); err != nil {
		_ = rollback()
		return "", nil, err
	}
	// The sidecar contains only integrity metadata and the target SID allow-list.
	// Standard-user hook processes must be able to read it to decide whether the
	// invoking SID is registered; write access remains Administrator/System-only.
	if err := windowsManagedPolicyWriter(statePath, stateBody, true); err != nil {
		_ = rollback()
		return "", nil, err
	}
	if err := verifyWindowsClaudeManagedPolicy(path, body); err != nil {
		_ = rollback()
		return "", nil, err
	}
	return path, rollback, nil
}

func removeWindowsClaudeManagedPolicyTarget(targetSID *windows.SID) error {
	return windowsClaudeManagedPolicyTransaction(func() error {
		return removeWindowsClaudeManagedPolicyTargetUnlocked(targetSID)
	})
}

func removeWindowsClaudeManagedPolicyTargetUnlocked(targetSID *windows.SID) error {
	if targetSID == nil {
		return fmt.Errorf("enterprise hooks: target SID is required for managed policy removal")
	}
	path, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return err
	}
	statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
	policySnapshot, err := snapshotWindowsManagedFile(path)
	if err != nil {
		return err
	}
	stateSnapshot, err := snapshotWindowsManagedFile(statePath)
	if err != nil {
		return err
	}
	state, err := validateExistingWindowsManagedPolicyOwnership(policySnapshot, stateSnapshot)
	if err != nil {
		return err
	}
	if !policySnapshot.existed {
		return nil
	}

	target := targetSID.String()
	remaining := make([]string, 0, len(state.TargetSIDs))
	found := false
	for _, sid := range state.TargetSIDs {
		if strings.EqualFold(strings.TrimSpace(sid), target) {
			found = true
			continue
		}
		remaining = append(remaining, sid)
	}
	if !found {
		return nil
	}
	remaining = sortedUnique(remaining)

	rollback := func(cause error) error {
		var failures []string
		for _, snapshot := range []windowsManagedFileSnapshot{policySnapshot, stateSnapshot} {
			if restoreErr := restoreWindowsManagedFile(snapshot); restoreErr != nil {
				failures = append(failures, restoreErr.Error())
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("%v (managed policy rollback failed: %s)", cause, strings.Join(failures, "; "))
		}
		return cause
	}

	if len(remaining) > 0 {
		state.TargetSIDs = remaining
		stateBody, marshalErr := json.MarshalIndent(state, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		stateBody = append(stateBody, '\n')
		if err := windowsManagedPolicyWriter(statePath, stateBody, true); err != nil {
			return rollback(err)
		}
		if err := verifyWindowsClaudeManagedPolicy(path, policySnapshot.data); err != nil {
			return rollback(err)
		}
		return nil
	}

	if err := os.Remove(path); err != nil {
		return rollback(fmt.Errorf("enterprise hooks: remove Claude Code managed hook policy: %w", err))
	}
	if err := os.Remove(statePath); err != nil {
		return rollback(fmt.Errorf("enterprise hooks: remove Claude Code managed hook ownership metadata: %w", err))
	}
	for _, removed := range []string{path, statePath} {
		if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = fmt.Errorf("artifact still exists")
			}
			return rollback(fmt.Errorf("enterprise hooks: verify managed policy removal for %s: %w", removed, err))
		}
	}
	return nil
}

func validateExistingWindowsManagedPolicyOwnership(policy, state windowsManagedFileSnapshot) (windowsClaudeManagedPolicyState, error) {
	if policy.existed != state.existed {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata is incomplete; refusing to overwrite %s", policy.path)
	}
	if !policy.existed {
		return windowsClaudeManagedPolicyState{}, nil
	}
	if err := windowsManagedPolicyFileTrustCheck(policy.path); err != nil {
		return windowsClaudeManagedPolicyState{}, err
	}
	if err := windowsManagedPolicyFileTrustCheck(state.path); err != nil {
		return windowsClaudeManagedPolicyState{}, err
	}
	var parsed windowsClaudeManagedPolicyState
	if err := json.Unmarshal(state.data, &parsed); err != nil || parsed.SchemaVersion != 1 {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: invalid Claude Code managed policy ownership metadata")
	}
	if parsed.PolicySHA256 != windowsManagedPolicyDigest(policy.data) {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: Claude Code managed policy was changed outside DefenseClaw; refusing to overwrite administrator edits")
	}
	if !filepath.IsAbs(parsed.HookExecutable) || filepath.Clean(parsed.HookExecutable) != parsed.HookExecutable {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: invalid Claude Code managed policy hook executable ownership metadata")
	}
	if len(parsed.TargetSIDs) == 0 {
		return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata has no target SIDs")
	}
	seen := make(map[string]struct{}, len(parsed.TargetSIDs))
	for _, rawSID := range parsed.TargetSIDs {
		sid, err := windows.StringToSid(strings.TrimSpace(rawSID))
		if err != nil || windowsEnterpriseSystemIdentity(sid) {
			return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: invalid target SID %q in Claude Code managed policy ownership metadata", rawSID)
		}
		canonical := sid.String()
		if _, duplicate := seen[canonical]; duplicate {
			return windowsClaudeManagedPolicyState{}, fmt.Errorf("enterprise hooks: duplicate target SID %q in Claude Code managed policy ownership metadata", rawSID)
		}
		seen[canonical] = struct{}{}
	}
	return parsed, nil
}

func inspectWindowsClaudeFilePolicyCompatibility(policyPath string) error {
	root := filepath.Dir(filepath.Dir(policyPath))
	paths := []string{filepath.Join(root, "managed-settings.json")}
	dropin := filepath.Dir(policyPath)
	entries, err := os.ReadDir(dropin)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("enterprise hooks: inspect Claude Code managed policy drop-ins: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(strings.ToLower(name), ".json") || strings.EqualFold(name, windowsClaudeManagedPolicyFile) {
			continue
		}
		paths = append(paths, filepath.Join(dropin, name))
	}
	sort.Slice(paths[1:], func(i, j int) bool {
		return strings.ToLower(filepath.Base(paths[1:][i])) < strings.ToLower(filepath.Base(paths[1:][j]))
	})
	disableAllHooks := false
	policyHelper := false
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("enterprise hooks: read Claude Code managed policy %s: %w", path, err)
		}
		if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
			return fmt.Errorf("enterprise hooks: untrusted Claude Code managed policy source %s: %w", path, err)
		}
		if len(data) > 4<<20 {
			return fmt.Errorf("enterprise hooks: Claude Code managed policy is too large: %s", path)
		}
		settings := map[string]interface{}{}
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("enterprise hooks: parse Claude Code managed policy %s: %w", path, err)
		}
		if raw, exists := settings["disableAllHooks"]; exists {
			value, ok := raw.(bool)
			if !ok {
				return fmt.Errorf("enterprise hooks: Claude Code managed disableAllHooks is not boolean in %s", path)
			}
			disableAllHooks = value
		}
		if raw, exists := settings["policyHelper"]; exists {
			policyHelper = raw != nil
		}
	}
	if policyHelper {
		return fmt.Errorf("enterprise hooks: Claude Code policyHelper supersedes file-based managed hooks; add DefenseClaw hooks to the helper output")
	}
	if disableAllHooks {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy disables all hooks")
	}
	return nil
}

func ensureWindowsManagedPolicyDirectory(path string) error {
	if err := rejectWindowsReparseChain(path); err != nil {
		return err
	}
	root := filepath.Dir(path)
	rootExisted := windowsPathExists(root)
	dropinExisted := windowsPathExists(path)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("enterprise hooks: create Claude Code managed policy directory: %w", err)
	}
	for _, item := range []struct {
		path    string
		existed bool
	}{{root, rootExisted}, {path, dropinExisted}} {
		if item.existed {
			if err := windowsManagedPolicyDirTrustCheck(item.path); err != nil {
				return err
			}
			continue
		}
		if err := setWindowsManagedPolicyProtection(item.path, true, false); err != nil {
			return fmt.Errorf("enterprise hooks: harden Claude Code managed policy directory %s: %w", item.path, err)
		}
	}
	return windowsManagedPolicyDirTrustCheck(path)
}

func writeWindowsManagedFile(path string, data []byte, userReadable bool) error {
	if err := rejectWindowsReparseChain(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing non-regular managed policy file: %s", path)
		}
		if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
			return err
		}
		if current, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(current, data) {
			if err := setWindowsManagedPolicyProtection(path, false, userReadable); err != nil {
				return err
			}
			return windowsManagedPolicyFileTrustCheck(path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".defenseclaw-policy-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := func() { _ = os.Remove(tempPath) }
	defer cleanup()
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := setWindowsManagedPolicyProtection(tempPath, false, userReadable); err != nil {
		return err
	}
	if err := safefile.ReplaceFile(tempPath, path); err != nil {
		return fmt.Errorf("enterprise hooks: publish managed policy %s: %w", path, err)
	}
	if err := setWindowsManagedPolicyProtection(path, false, userReadable); err != nil {
		return err
	}
	return windowsManagedPolicyFileTrustCheck(path)
}

func setWindowsManagedPolicyProtection(path string, directory, userReadable bool) error {
	owner, err := windowsManagedPolicyOwnerSID()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{}
	for _, sid := range []*windows.SID{owner, system} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	if directory || userReadable {
		permission := windows.ACCESS_MASK(windows.GENERIC_READ)
		if directory {
			permission |= windows.GENERIC_EXECUTE
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: permission,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP, TrusteeValue: windows.TrusteeValueFromSID(users)},
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
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func verifyWindowsClaudeManagedPolicy(path string, expected []byte) error {
	if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, expected) {
		return fmt.Errorf("enterprise hooks: persisted Claude Code managed policy bytes differ from the verified render")
	}
	statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
	if err := windowsManagedPolicyFileTrustCheck(statePath); err != nil {
		return err
	}
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		return err
	}
	var state windowsClaudeManagedPolicyState
	if err := json.Unmarshal(stateData, &state); err != nil || state.SchemaVersion != 1 || state.PolicySHA256 != windowsManagedPolicyDigest(data) {
		return fmt.Errorf("enterprise hooks: Claude Code managed policy ownership metadata does not match the policy")
	}
	return nil
}

func snapshotWindowsManagedFile(path string) (windowsManagedFileSnapshot, error) {
	snapshot := windowsManagedFileSnapshot{path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > windowsClaudeManagedStateLimit {
		return snapshot, fmt.Errorf("enterprise hooks: refusing unsafe managed policy artifact: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, err
	}
	snapshot.existed = true
	snapshot.data = data
	return snapshot, nil
}

func restoreWindowsManagedFile(snapshot windowsManagedFileSnapshot) error {
	if snapshot.existed {
		return writeWindowsManagedFile(snapshot.path, snapshot.data, true)
	}
	if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func windowsManagedPolicyDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func windowsPathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
