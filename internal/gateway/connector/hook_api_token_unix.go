// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/runtimeowner"
)

// Unix custody is represented by the existing owner/mode/ACL checks. Windows
// carries an additional exact owner/DACL witness in this platform slot.
type hookAPITokenPublishProtection struct{}

func captureHookAPITokenPublishProtectionPlatform(
	file *os.File, info os.FileInfo,
) (hookAPITokenPublishProtection, bool, error) {
	return hookAPITokenPublishProtection{}, otlpValidatePerm(file.Name(), info) == nil, nil
}

func applyHookAPITokenPublishProtectionPlatform(
	_ *os.File, _ hookAPITokenPublishProtection,
) error {
	return nil
}

func hookAPITokenPublishProtectionIsZero(hookAPITokenPublishProtection) bool { return true }

func hookAPITokenPublishProtectionsEqual(_, _ hookAPITokenPublishProtection) bool { return true }

func hookAPIValidateOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if hookAPITrustedOwner(stat.Uid) {
		return nil
	}
	return tokenPermissionVerdict(fmt.Errorf(
		"hook API token %s uid %d is not root, effective uid %d, real uid %d, or the defenseclaw service uid",
		path, stat.Uid, os.Geteuid(), os.Getuid(),
	))
}

func hookAPIValidateDirectory(path string) error {
	return hookAPIValidateDirectoryWith(path, false)
}

// Agent-created connector directories may use a proven private primary group.
// Hook token, data and socket directories keep the strict directory check.
func hookAPIValidateAgentDirectory(path string) error {
	return hookAPIValidateDirectoryWith(path, true)
}

func hookAPIValidateDirectoryWith(path string, agentDirectory bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook API token directory must be absolute: %q", path)
	}
	clean := filepath.Clean(path)
	if err := hookAPIValidateDirectoryChainWith(clean, agentDirectory); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return err
	}
	if resolved != clean {
		return hookAPIValidateDirectoryChainWith(resolved, agentDirectory)
	}
	return nil
}

func hookAPIValidateDirectoryElement(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook API token directory must be absolute: %q", path)
	}
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks are not allowed: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("expected directory: %s", path)
	}
	return hookAPIValidateDirectoryMetadata(path, info, false, false)
}

// hookAPIValidateDirectoryChain walks every ancestor of clean. Ancestors inside
// the Cisco Secure Client tree get advisory permission verdicts (AIFW-34262):
// AVC owns and re-ACLs `/opt/cisco/secureclient`, and the managed data and hooks
// directories live below it, so drift there must not stop the gateway from
// binding its hook API. The named directory, every ancestor outside that tree,
// and every structural failure anywhere stay fatal.
func hookAPIValidateDirectoryChain(clean string) error {
	return hookAPIValidateDirectoryChainWith(clean, false)
}

func hookAPIValidateDirectoryChainWith(clean string, agentDirectory bool) error {
	for cur := clean; ; cur = filepath.Dir(cur) {
		advisory := cur != clean && managed.AdvisoryAncestorPath(cur)
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if hookAPISymlinkRefused(cur, clean, info) {
				return fmt.Errorf("symlinks are not allowed: %s", cur)
			}
			targetInfo, err := os.Stat(cur)
			if err != nil {
				return err
			}
			if !targetInfo.IsDir() {
				return fmt.Errorf("expected directory: %s", cur)
			}
			if cur == filepath.Dir(cur) {
				break
			}
			continue
		}
		if !info.IsDir() {
			return fmt.Errorf("expected directory: %s", cur)
		}
		if err := hookAPIValidateDirectoryMetadataWith(cur, info, cur != clean, advisory, agentDirectory); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

// hookAPISymlinkRefused is the walk's decision on a link in the folder chain
// of clean: the named folder itself is never a link, and an ancestor may be one
// only when it is a root-owned system link (a macOS root alias or a link inside
// a root-owned private parent). The plugin-custody explainer asks this same
// function so it never offers a permission fix for a link.
func hookAPISymlinkRefused(cur, clean string, info os.FileInfo) bool {
	return cur == clean || (!hookAPITrustedDarwinRootAlias(cur) && !hookAPITrustedSystemSymlink(cur, info))
}

func hookAPITrustedDarwinRootAlias(path string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	switch filepath.Clean(path) {
	case "/etc", "/tmp", "/var":
		return true
	default:
		return false
	}
}

func hookAPITrustedSystemSymlink(path string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return false
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	return ok && parentStat.Uid == 0
}

// hookAPIValidateDirectoryMetadata judges one element. With advisory set, the
// mode, owner, and ACL verdicts become TrustAdvisoryMarker warnings; failures to
// inspect the element at all stay fatal, as does an ACL helper that could not
// read or parse the ACL (only its judgements are tagged as downgradable).
func hookAPIValidateDirectoryMetadata(path string, info os.FileInfo, allowStickyAncestor, advisory bool) error {
	return hookAPIValidateDirectoryMetadataWith(path, info, allowStickyAncestor, advisory, false)
}

func hookAPIValidateDirectoryMetadataWith(path string, info os.FileInfo, allowStickyAncestor, advisory, agentDirectory bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect directory owner: %s", path)
	}
	const label = "hook API token path"
	mode := info.Mode().Perm()
	otherAccountsWritable := mode&0o022 != 0
	if agentDirectory && mode&0o022 == 0o020 && ownerPrivateGroup(path, info) {
		otherAccountsWritable = false
	}
	if otherAccountsWritable &&
		((!(allowStickyAncestor) || info.Mode()&os.ModeSticky == 0) || stat.Uid != 0) {
		if err := managed.RelaxAncestorTrustVerdict(advisory, path, label, fmt.Errorf(
			"%s has group/other writable mode %04o", path, mode,
		)); err != nil {
			return tokenPermissionVerdict(err)
		}
	}
	if !hookAPITrustedOwner(stat.Uid) {
		if err := managed.RelaxAncestorTrustVerdict(advisory, path, label, fmt.Errorf(
			"%s uid %d is not root, effective uid %d, real uid %d, or the defenseclaw service uid",
			path, stat.Uid, os.Geteuid(), os.Getuid(),
		)); err != nil {
			return tokenPermissionVerdict(err)
		}
	}
	return managed.RelaxAncestorTrustJudgement(advisory, path, label, hookAPIValidateDirectoryACL(path))
}

func hookAPITrustedOwner(uid uint32) bool {
	// Real/effective-UID ownership is intentional for unmanaged installs and
	// privileged enterprise reconciliation. The latter keeps real uid 0 while
	// temporarily dropping effective uid to the manifest-pinned target user;
	// files that user just created must be validated against the effective uid.
	// Accepting both preserves the unmanaged/setuid compatibility contract.
	if runtimeowner.Trusted(uid) {
		return true
	}
	for _, name := range hookAPIServiceAccounts(runtime.GOOS) {
		serviceUser, err := hookAPILookupUser(name)
		if err != nil || serviceUser == nil {
			continue
		}
		serviceUID, err := strconv.ParseUint(serviceUser.Uid, 10, 32)
		if err == nil && uid == uint32(serviceUID) {
			return true
		}
	}
	return false
}

var hookAPILookupUser = user.Lookup

// hookAPIServiceAccounts names the gateway service accounts whose data
// directories hold hook tokens: "defenseclaw" everywhere, plus the hidden
// "_defenseclaw" account the standalone macOS deployment runs the gateway as.
func hookAPIServiceAccounts(goos string) []string {
	if goos == "darwin" {
		return []string{managed.StandaloneLinuxServiceUser, managed.StandaloneDarwinServiceUser}
	}
	return []string{managed.StandaloneLinuxServiceUser}
}

// hookAPIValidateOwnerFor matches the Windows signature; Unix guardians act
// with the target user's own credentials, so no extra owner is trusted.
func hookAPIValidateOwnerFor(path string, info os.FileInfo, _ string) error {
	return hookAPIValidateOwner(path, info)
}

// Plugin files are loaded as policy code. Their own write authority must be
// checked as well as the directory chain, including an existing file's ACL.
func hookAPIValidatePluginFilePermissions(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode&0o002 != 0 || (mode&0o020 != 0 && !ownerPrivateGroup(path, info)) {
		return fmt.Errorf("plugin target %s has group/other writable mode %04o", path, mode)
	}
	return hookAPIValidateDirectoryACL(path)
}

// hookAPIValidateDirectoryFor matches the Windows signature (see
// hookAPIValidateOwnerFor).
func hookAPIValidateDirectoryFor(path, _ string) error {
	return hookAPIValidateAgentDirectory(path)
}

// mkdirHookAPITokenDir creates the hooks directory private to its owner.
func mkdirHookAPITokenDir(hooksDir string) error {
	return os.Mkdir(hooksDir, 0o700)
}

// mkdirHookAPITokenParents makes the missing directories above the hooks
// directory, private to their owner.
func mkdirHookAPITokenParents(dir string) error {
	return os.MkdirAll(dir, 0o700)
}
