// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	windowsCursorManagedHooksFile    = "hooks.json"
	windowsCursorManagedAdapterFile  = "defenseclaw-hook.ps1"
	windowsCursorManagedStateFile    = ".defenseclaw-managed-hooks.state"
	windowsCursorManagedReceiptFile  = ".defenseclaw-managed-hooks.receipt"
	windowsCursorManagedLockFile     = ".defenseclaw-managed-hooks.lock"
	windowsCursorManagedHooksLimit   = 4 << 20
	windowsCursorManagedStateLimit   = 8 << 20
	windowsCursorManagedReceiptLimit = 8 << 20
	windowsCursorManagedAdapterLimit = 1 << 20
)

var windowsCursorManagedRootResolver = defaultWindowsCursorManagedRoot

// windowsCursorManagedGuardRebuildBeforeWrite runs just before the guard
// rebuild swaps each artifact; tests use it to edit a file concurrently.
var windowsCursorManagedGuardRebuildBeforeWrite = func(string) {}

// WindowsCursorManagedRuntimeTarget binds a machine-authorized SID to only
// that user's canonical DefenseClaw runtime. No token is stored in ProgramData.
type WindowsCursorManagedRuntimeTarget struct {
	SID     string `json:"sid"`
	DataDir string `json:"data_dir"`
}

type windowsCursorManagedPolicyState struct {
	HookFailMode       string                              `json:"hook_fail_mode,omitempty"`
	TargetFailModes    map[string]string                   `json:"target_fail_modes,omitempty"`
	SchemaVersion      int                                 `json:"schema_version"`
	HookExecutable     string                              `json:"hook_executable"`
	GatewayAddr        string                              `json:"gateway_addr"`
	GatewayServiceName string                              `json:"gateway_service_name"`
	AdapterSHA256      string                              `json:"adapter_sha256"`
	ReceiptSHA256      string                              `json:"receipt_sha256"`
	Targets            []WindowsCursorManagedRuntimeTarget `json:"targets"`
}

// windowsCursorManagedPolicyReceipt is administrator-only rollback material.
// It is deliberately separate from the user-readable SID registry.
type windowsCursorManagedPolicyReceipt struct {
	SchemaVersion                    int    `json:"schema_version"`
	ConfigPreexisting                bool   `json:"config_preexisting"`
	ConfigOriginal                   []byte `json:"config_original,omitempty"`
	ConfigOriginalSHA256             string `json:"config_original_sha256,omitempty"`
	ConfigOriginalSecurityDescriptor string `json:"config_original_security_descriptor,omitempty"`
	ConfigOriginalAttributes         uint32 `json:"config_original_attributes,omitempty"`
}

// WindowsCursorManagedPolicyTeardownOptions authenticates the exact global
// Cursor enrollment expected by an installer lifecycle transaction.
type WindowsCursorManagedPolicyTeardownOptions struct {
	HookExecutable     string
	GatewayAddr        string
	GatewayServiceName string
	Targets            []WindowsCursorManagedRuntimeTarget
}

// WindowsCursorManagedPolicyTeardownSnapshot contains the singleton Cursor
// enterprise artifacts. It is serialized only into the protected installer
// transaction journal.
type WindowsCursorManagedPolicyTeardownSnapshot struct {
	PolicyActive              bool   `json:"policy_active"`
	HooksExisted              bool   `json:"hooks_existed"`
	Hooks                     []byte `json:"hooks,omitempty"`
	HooksSecurityDescriptor   string `json:"hooks_security_descriptor,omitempty"`
	HooksAttributes           uint32 `json:"hooks_attributes,omitempty"`
	AdapterExisted            bool   `json:"adapter_existed"`
	Adapter                   []byte `json:"adapter,omitempty"`
	AdapterSecurityDescriptor string `json:"adapter_security_descriptor,omitempty"`
	AdapterAttributes         uint32 `json:"adapter_attributes,omitempty"`
	StateExisted              bool   `json:"state_existed"`
	State                     []byte `json:"state,omitempty"`
	StateSecurityDescriptor   string `json:"state_security_descriptor,omitempty"`
	StateAttributes           uint32 `json:"state_attributes,omitempty"`
	ReceiptExisted            bool   `json:"receipt_existed"`
	Receipt                   []byte `json:"receipt,omitempty"`
	ReceiptSecurityDescriptor string `json:"receipt_security_descriptor,omitempty"`
	ReceiptAttributes         uint32 `json:"receipt_attributes,omitempty"`
}

type windowsCursorManagedFileMetadata struct {
	securityDescriptor string
	attributes         uint32
}

type windowsCursorManagedArtifacts struct {
	root            string
	hooks           windowsManagedFileSnapshot
	hooksMetadata   windowsCursorManagedFileMetadata
	adapter         windowsManagedFileSnapshot
	adapterMetadata windowsCursorManagedFileMetadata
	state           windowsManagedFileSnapshot
	stateMetadata   windowsCursorManagedFileMetadata
	receipt         windowsManagedFileSnapshot
	receiptMetadata windowsCursorManagedFileMetadata
	parsed          windowsCursorManagedPolicyState
	parsedReceipt   windowsCursorManagedPolicyReceipt
	active          bool
}

type windowsCursorManagedPolicyTarget struct {
	dataDir            string
	hookExecutable     string
	gatewayAddr        string
	gatewayServiceName string
	targetSID          *windows.SID
	registered         bool
	active             bool
	hookFailMode       string
}

func defaultWindowsCursorManagedRoot() (string, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve trusted ProgramData for Cursor: %w", err)
	}
	return filepath.Join(programData, "Cursor"), nil
}

// windowsCursorPaths carries every managed leaf path derived from the
// resolved Cursor enterprise root. Callers bind the fields they need by
// name, which prevents a swap between two same-typed positional string
// return values from silently pointing at the wrong path.
type windowsCursorPaths struct {
	Root    string
	Hooks   string
	Adapter string
	State   string
	Receipt string
	Lock    string
}

func windowsCursorManagedPaths() (windowsCursorPaths, error) {
	root, err := windowsCursorManagedRootResolver()
	if err != nil {
		return windowsCursorPaths{}, err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!strings.EqualFold(filepath.Base(root), "Cursor") {
		return windowsCursorPaths{}, fmt.Errorf(
			"enterprise hooks: refusing noncanonical Cursor enterprise root: %s",
			root,
		)
	}
	return windowsCursorPaths{
		Root:    root,
		Hooks:   filepath.Join(root, windowsCursorManagedHooksFile),
		Adapter: filepath.Join(root, windowsCursorManagedAdapterFile),
		State:   filepath.Join(root, windowsCursorManagedStateFile),
		Receipt: filepath.Join(root, windowsCursorManagedReceiptFile),
		Lock:    filepath.Join(root, windowsCursorManagedLockFile),
	}, nil
}

func withWindowsCursorManagedTransaction(fn func() error) error {
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
	root := paths.Root
	lockPath := paths.Lock
	if err := ensureWindowsManagedPolicyDirectory(root); err != nil {
		return fmt.Errorf("enterprise hooks: prepare Cursor enterprise directory: %w", err)
	}
	if err := validateWindowsManagedPolicyDirectoryProtection(root); err != nil {
		return fmt.Errorf("enterprise hooks: verify exact Cursor enterprise directory protection: %w", err)
	}
	if info, statErr := os.Lstat(lockPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing non-regular Cursor transaction lock: %s", lockPath)
		}
		if err := windowsManagedPolicyFileTrustCheck(lockPath); err != nil {
			return fmt.Errorf("enterprise hooks: Cursor transaction lock is untrusted: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("enterprise hooks: inspect Cursor transaction lock: %w", statErr)
	}

	deadline := time.Now().Add(windowsClaudeManagedLockTimeout)
	for {
		lock, lockErr := openWindowsClaudeManagedPolicyLockFile(lockPath)
		if lockErr == nil {
			closed := false
			defer func() {
				if !closed {
					_ = windows.CloseHandle(lock)
				}
			}()
			if err := setWindowsManagedPolicyProtection(lockPath, false, false); err != nil {
				_ = windows.CloseHandle(lock)
				closed = true
				return fmt.Errorf("enterprise hooks: harden Cursor transaction lock: %w", err)
			}
			if err := windowsManagedPolicyFileTrustCheck(lockPath); err != nil {
				_ = windows.CloseHandle(lock)
				closed = true
				return fmt.Errorf("enterprise hooks: verify Cursor transaction lock: %w", err)
			}
			transactionErr := fn()
			artifacts, snapshotErr := snapshotWindowsCursorManagedArtifacts()
			retireLock := snapshotErr == nil && windowsCursorManagedLockCanRetire(artifacts)
			closeErr := windows.CloseHandle(lock)
			closed = closeErr == nil
			var retireErr error
			if closeErr == nil && retireLock {
				retireErr = retireWindowsCursorManagedLock(lockPath)
			}
			return errors.Join(transactionErr, snapshotErr, closeErr, retireErr)
		}
		if !errors.Is(lockErr, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(lockErr, windows.ERROR_LOCK_VIOLATION) {
			return fmt.Errorf("enterprise hooks: acquire Cursor transaction lock: %w", lockErr)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("enterprise hooks: timed out waiting for Cursor transaction lock")
		}
		time.Sleep(windowsClaudeManagedLockRetry)
	}
}

// windowsCursorManagedLockCanRetire is deliberately stricter than checking
// only the public state file. The transaction lock is removed only when the
// adapter, state, and private receipt are absent and hooks.json contains no
// DefenseClaw-owned Cursor entry. A tombstone or malformed/ambiguous config
// keeps the protected lock in place.
func windowsCursorManagedLockCanRetire(artifacts windowsCursorManagedArtifacts) bool {
	if artifacts.adapter.existed || artifacts.state.existed || artifacts.receipt.existed {
		return false
	}
	if !artifacts.hooks.existed {
		return true
	}
	cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(
		artifacts.hooks.data,
		artifacts.adapter.path,
	)
	return err == nil && connector.WindowsCursorEnterpriseHooksSemanticallyEqual(
		cleaned,
		artifacts.hooks.data,
	)
}

func retireWindowsCursorManagedLock(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("enterprise hooks: retire unused Cursor transaction lock: %w", err)
	}
	return nil
}

func snapshotWindowsCursorManagedArtifacts() (windowsCursorManagedArtifacts, error) {
	result, err := snapshotWindowsCursorManagedPublicArtifacts()
	if err != nil {
		return result, err
	}
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		return result, err
	}
	receiptPath := paths.Receipt
	result.receipt, err = snapshotWindowsManagedFileWithLimit(receiptPath, windowsCursorManagedReceiptLimit)
	if err != nil {
		return result, err
	}
	result.receiptMetadata, err = snapshotWindowsCursorManagedFileMetadata(result.receipt)
	if err != nil {
		return result, err
	}
	return result, nil
}

func snapshotWindowsCursorManagedPublicArtifacts() (windowsCursorManagedArtifacts, error) {
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		return windowsCursorManagedArtifacts{}, err
	}
	hooksPath := paths.Hooks
	adapterPath := paths.Adapter
	statePath := paths.State
	result := windowsCursorManagedArtifacts{root: paths.Root}
	result.hooks, err = snapshotWindowsManagedFileWithLimit(hooksPath, windowsCursorManagedHooksLimit)
	if err != nil {
		return result, err
	}
	result.hooksMetadata, err = snapshotWindowsCursorManagedFileMetadata(result.hooks)
	if err != nil {
		return result, err
	}
	result.adapter, err = snapshotWindowsManagedFileWithLimit(adapterPath, windowsCursorManagedAdapterLimit)
	if err != nil {
		return result, err
	}
	result.adapterMetadata, err = snapshotWindowsCursorManagedFileMetadata(result.adapter)
	if err != nil {
		return result, err
	}
	result.state, err = snapshotWindowsManagedFileWithLimit(statePath, windowsCursorManagedStateLimit)
	if err != nil {
		return result, err
	}
	result.stateMetadata, err = snapshotWindowsCursorManagedFileMetadata(result.state)
	if err != nil {
		return result, err
	}
	return result, nil
}

func snapshotWindowsCursorManagedFileMetadata(
	snapshot windowsManagedFileSnapshot,
) (windowsCursorManagedFileMetadata, error) {
	if !snapshot.existed {
		return windowsCursorManagedFileMetadata{}, nil
	}
	extended, err := winpath.Extended(snapshot.path)
	if err != nil {
		return windowsCursorManagedFileMetadata{}, err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || descriptor.String() == "" {
		if err == nil {
			err = errors.New("empty security descriptor")
		}
		return windowsCursorManagedFileMetadata{}, fmt.Errorf(
			"enterprise hooks: snapshot Cursor security descriptor for %s: %w",
			snapshot.path,
			err,
		)
	}
	pointer, err := winpath.UTF16Ptr(snapshot.path)
	if err != nil {
		return windowsCursorManagedFileMetadata{}, err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return windowsCursorManagedFileMetadata{}, fmt.Errorf(
			"enterprise hooks: snapshot Cursor attributes for %s: %w",
			snapshot.path,
			err,
		)
	}
	if attributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return windowsCursorManagedFileMetadata{}, fmt.Errorf(
			"enterprise hooks: refusing unsafe Cursor file attributes for %s",
			snapshot.path,
		)
	}
	return windowsCursorManagedFileMetadata{
		securityDescriptor: descriptor.String(),
		attributes:         attributes,
	}, nil
}

func restoreWindowsCursorManagedFileMetadata(
	path string,
	metadata windowsCursorManagedFileMetadata,
) error {
	if metadata.securityDescriptor == "" {
		return errors.New("enterprise hooks: Cursor file snapshot has no security descriptor")
	}
	descriptor, err := windows.SecurityDescriptorFromString(metadata.securityDescriptor)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("enterprise hooks: Cursor file snapshot has an invalid security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return errors.New("enterprise hooks: Cursor file snapshot has no valid owner")
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Cursor snapshot group: %w", err)
	}
	// DACL's boolean result reports whether the ACL was defaulted; a missing
	// DACL is reported through err. Do not mistake an explicit (non-defaulted)
	// DACL for an absent one.
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("enterprise hooks: Cursor file snapshot has no trusted DACL")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Cursor snapshot DACL control: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		securityInformation |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		securityInformation |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		securityInformation,
		owner,
		group,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("enterprise hooks: restore Cursor security descriptor for %s: %w", path, err)
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	if err := windows.SetFileAttributes(pointer, metadata.attributes); err != nil {
		return fmt.Errorf("enterprise hooks: restore Cursor attributes for %s: %w", path, err)
	}
	if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
		return fmt.Errorf("enterprise hooks: restored Cursor metadata is untrusted for %s: %w", path, err)
	}
	return nil
}

func restoreWindowsCursorManagedFile(snapshot windowsManagedFileSnapshot, metadata windowsCursorManagedFileMetadata) error {
	if !snapshot.existed {
		if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	userReadable := !strings.EqualFold(filepath.Base(snapshot.path), windowsCursorManagedReceiptFile)
	if err := windowsManagedPolicyWriter(snapshot.path, snapshot.data, userReadable); err != nil {
		return err
	}
	return restoreWindowsCursorManagedFileMetadata(snapshot.path, metadata)
}

func writeWindowsCursorPrivateReceipt(path string, data []byte) error {
	if err := windowsManagedPolicyWriter(path, data, false); err != nil {
		return err
	}
	// writeWindowsManagedFile intentionally skips an identical byte rewrite.
	// Reapply the private ACL anyway so a trusted-but-readable administrator
	// ACL change cannot persist on the receipt through repair or upgrade.
	if err := setWindowsManagedPolicyProtection(path, false, false); err != nil {
		return fmt.Errorf("enterprise hooks: harden Cursor rollback receipt: %w", err)
	}
	if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
		return fmt.Errorf("enterprise hooks: verify Cursor rollback receipt protection: %w", err)
	}
	return nil
}

func windowsCursorManagedFileSnapshotEqual(
	left windowsManagedFileSnapshot,
	leftMetadata windowsCursorManagedFileMetadata,
	right windowsManagedFileSnapshot,
	rightMetadata windowsCursorManagedFileMetadata,
) bool {
	return left.existed == right.existed &&
		bytes.Equal(left.data, right.data) &&
		leftMetadata == rightMetadata
}

func validateWindowsCursorManagedArtifacts(
	artifacts windowsCursorManagedArtifacts,
) (windowsCursorManagedArtifacts, error) {
	artifacts, err := validateWindowsCursorManagedPublicArtifacts(artifacts)
	if err != nil {
		return artifacts, err
	}
	if !artifacts.active {
		if artifacts.receipt.existed {
			return artifacts, errors.New("enterprise hooks: unowned Cursor rollback receipt already exists")
		}
		return artifacts, nil
	}
	return validateWindowsCursorManagedReceipt(artifacts)
}

func validateWindowsCursorManagedReceipt(
	artifacts windowsCursorManagedArtifacts,
) (windowsCursorManagedArtifacts, error) {
	if !artifacts.receipt.existed {
		return artifacts, errors.New("enterprise hooks: Cursor managed rollback receipt is missing")
	}
	if err := windowsManagedPolicyFileTrustCheck(artifacts.receipt.path); err != nil {
		return artifacts, fmt.Errorf("enterprise hooks: untrusted Cursor rollback receipt: %w", err)
	}
	if err := validateWindowsCursorPrivateReceiptMetadata(artifacts.receiptMetadata); err != nil {
		return artifacts, err
	}
	if artifacts.parsed.ReceiptSHA256 != windowsManagedPolicyDigest(artifacts.receipt.data) {
		return artifacts, errors.New("enterprise hooks: Cursor rollback receipt identity changed")
	}
	var receipt windowsCursorManagedPolicyReceipt
	receiptDecoder := json.NewDecoder(bytes.NewReader(artifacts.receipt.data))
	receiptDecoder.DisallowUnknownFields()
	if err := receiptDecoder.Decode(&receipt); err != nil {
		return artifacts, fmt.Errorf("enterprise hooks: parse Cursor managed rollback receipt: %w", err)
	}
	var trailing any
	if err := receiptDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return artifacts, errors.New("enterprise hooks: Cursor managed rollback receipt contains trailing JSON")
	}
	if receipt.SchemaVersion != 1 {
		return artifacts, errors.New("enterprise hooks: Cursor managed rollback receipt has an invalid schema")
	}
	if receipt.ConfigPreexisting {
		if receipt.ConfigOriginalSHA256 != windowsManagedPolicyDigest(receipt.ConfigOriginal) ||
			receipt.ConfigOriginalSecurityDescriptor == "" ||
			receipt.ConfigOriginalAttributes == 0 {
			return artifacts, errors.New("enterprise hooks: Cursor original enterprise config receipt is invalid")
		}
		if _, err := windows.SecurityDescriptorFromString(receipt.ConfigOriginalSecurityDescriptor); err != nil {
			return artifacts, errors.New("enterprise hooks: Cursor original enterprise config security receipt is invalid")
		}
	} else if len(receipt.ConfigOriginal) != 0 || receipt.ConfigOriginalSHA256 != "" ||
		receipt.ConfigOriginalSecurityDescriptor != "" || receipt.ConfigOriginalAttributes != 0 {
		return artifacts, errors.New("enterprise hooks: absent Cursor config has unexpected original bytes")
	}
	artifacts.parsedReceipt = receipt
	return artifacts, nil
}

// errWindowsCursorOrphanHookRefs reports DefenseClaw adapter references in
// the Cursor enterprise hooks.json while no protected ownership state exists.
var errWindowsCursorOrphanHookRefs = errors.New("enterprise hooks: Cursor hook references remain without ownership metadata")

// validateWindowsCursorManagedArtifactsReclaimingOrphans is the mutation-path
// form of validateWindowsCursorManagedArtifacts. Callers MUST hold
// withWindowsCursorManagedTransaction.
//
// Bulldoze reclaim (#1068): a prior scoped install stamped hook entries into
// hooks.json but its ownership metadata (state/receipt) is gone, either from a
// crash between the hooks write and the state write or from a manual clean-up
// that wiped only the sidecars. The entries are DefenseClaw's by adapter-path
// match, so outside strict mode hooks.json is rewritten with only those
// entries removed, through the metadata-preserving writer every other
// hooks.json write uses, and the re-read artifacts are validated again.
// Strict mode (DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS=1) keeps refusing.
func validateWindowsCursorManagedArtifactsReclaimingOrphans(
	current windowsCursorManagedArtifacts,
) (windowsCursorManagedArtifacts, error) {
	artifacts, err := validateWindowsCursorManagedArtifacts(current)
	if !errors.Is(err, errWindowsCursorOrphanHookRefs) || managed.TrustStrictAncestors() {
		return artifacts, err
	}
	cleaned, removeErr := connector.RemoveWindowsCursorEnterpriseHooks(current.hooks.data, current.adapter.path)
	if removeErr != nil {
		return artifacts, err
	}
	fmt.Fprintf(os.Stderr,
		"[enterprise-hooks] reclaiming orphan Cursor hook refs at %s (state ownership metadata absent)\n",
		current.hooks.path)
	if _, writeErr := publishWindowsCursorManagedHooks(current.hooks, func(base windowsManagedFileSnapshot) (windowsCursorManagedHooksEdit, error) {
		if !bytes.Equal(base.data, current.hooks.data) {
			var cleanErr error
			if cleaned, cleanErr = connector.RemoveWindowsCursorEnterpriseHooks(base.data, current.adapter.path); cleanErr != nil {
				return windowsCursorManagedHooksEdit{}, cleanErr
			}
		}
		return windowsCursorManagedHooksEdit{data: cleaned}, nil
	}); writeErr != nil {
		return artifacts, fmt.Errorf("enterprise hooks: reclaim orphan Cursor hook refs: %w", writeErr)
	}
	reclaimed, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		return reclaimed, err
	}
	return validateWindowsCursorManagedArtifacts(reclaimed)
}

func validateWindowsCursorManagedPublicArtifacts(
	artifacts windowsCursorManagedArtifacts,
) (windowsCursorManagedArtifacts, error) {
	if !artifacts.state.existed {
		if artifacts.adapter.existed && !bytes.Equal(artifacts.adapter.data, windowsCursorManagedTombstone()) {
			return artifacts, errors.New("enterprise hooks: unowned Cursor DefenseClaw adapter already exists")
		}
		if artifacts.hooks.existed {
			cleaned, removeErr := connector.RemoveWindowsCursorEnterpriseHooks(
				artifacts.hooks.data,
				artifacts.adapter.path,
			)
			if removeErr == nil &&
				!connector.WindowsCursorEnterpriseHooksSemanticallyEqual(cleaned, artifacts.hooks.data) {
				// Stay side-effect free: unlocked readers (every hook
				// process resolving its policy target, lifecycle restore
				// validation) reach this validator. Locked install and
				// repair paths reclaim through
				// validateWindowsCursorManagedArtifactsReclaimingOrphans.
				return artifacts, errWindowsCursorOrphanHookRefs
			}
		}
		artifacts.active = false
		return artifacts, nil
	}
	if !artifacts.hooks.existed || !artifacts.adapter.existed {
		return artifacts, errors.New("enterprise hooks: Cursor managed ownership metadata is incomplete")
	}
	if err := windowsManagedPolicyFileTrustCheck(artifacts.hooks.path); err != nil {
		return artifacts, fmt.Errorf("enterprise hooks: untrusted Cursor enterprise artifact %s: %w", artifacts.hooks.path, err)
	}
	artifacts, err := validateWindowsCursorManagedStateIdentity(artifacts)
	if err != nil {
		return artifacts, err
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooksForMigration(artifacts.hooks.data, artifacts.adapter.path, cursorManagedPolicyFailMode(artifacts.parsed)); err != nil {
		return artifacts, fmt.Errorf("enterprise hooks: verify Cursor enterprise hooks: %w", err)
	}
	artifacts.active = true
	return artifacts, nil
}

func validateWindowsCursorManagedStateIdentity(
	artifacts windowsCursorManagedArtifacts,
) (windowsCursorManagedArtifacts, error) {
	if !artifacts.state.existed || !artifacts.adapter.existed {
		return artifacts, errors.New("enterprise hooks: Cursor managed ownership metadata is incomplete")
	}
	for _, item := range []windowsManagedFileSnapshot{artifacts.adapter, artifacts.state} {
		if err := windowsManagedPolicyFileTrustCheck(item.path); err != nil {
			return artifacts, fmt.Errorf("enterprise hooks: untrusted Cursor enterprise artifact %s: %w", item.path, err)
		}
	}
	var state windowsCursorManagedPolicyState
	decoder := json.NewDecoder(bytes.NewReader(artifacts.state.data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return artifacts, fmt.Errorf("enterprise hooks: parse Cursor managed ownership metadata: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return artifacts, errors.New("enterprise hooks: Cursor managed ownership metadata contains trailing JSON")
		}
		return artifacts, fmt.Errorf("enterprise hooks: parse trailing Cursor ownership metadata: %w", err)
	}
	if (state.HookFailMode != "" && state.HookFailMode != "open" && state.HookFailMode != "closed") || state.SchemaVersion != 1 || !filepath.IsAbs(state.HookExecutable) ||
		filepath.Clean(state.HookExecutable) != state.HookExecutable ||
		!validWindowsCursorManagedDigest(state.ReceiptSHA256) {
		return artifacts, errors.New("enterprise hooks: invalid Cursor managed ownership identity")
	}
	gateway, err := connector.NormalizeWindowsManagedGatewayAddr(state.GatewayAddr)
	if err != nil || gateway != state.GatewayAddr {
		return artifacts, errors.New("enterprise hooks: invalid Cursor managed gateway address")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(state.GatewayServiceName); err != nil {
		return artifacts, err
	}
	targets, err := canonicalWindowsCursorManagedTargets(state.Targets, false)
	if err != nil {
		return artifacts, errors.New("enterprise hooks: invalid Cursor managed target set")
	}
	if len(targets) == 0 && (state.TargetFailModes != nil || cursorManagedPolicyFailMode(state) != "closed") {
		return artifacts, errors.New("enterprise hooks: empty Cursor enrollment must retain a closed machine hook")
	}
	state.Targets = targets
	// The per-target delivery modes must be consistent with the enrollment
	// and the shared failClosed flag (#1163); the adapter body itself is
	// matched against the recorded digest, not this build's template, so an
	// upgrade can still snapshot and refresh it (GAP-2467).
	if _, err := renderWindowsCursorManagedAdapter(state); err != nil {
		return artifacts, err
	}
	if !windowsCursorManagedAdapterMatchesState(state, artifacts.adapter.data) {
		return artifacts, errors.New("enterprise hooks: Cursor enterprise adapter identity changed")
	}
	artifacts.parsed = state
	return artifacts, nil
}

// windowsCursorManagedAdapterMatchesState reports whether adapter is the
// exact body the protected ownership state recorded for its hook executable.
// It does not require the current build's template: the adapter template
// changes between releases, and an upgrade must still snapshot, replace and
// restore the adapter an earlier release installed (GAP-1068). Install and
// the guardian's RefreshWindowsCursorManagedAdapter rewrite the adapter from
// the current template, and the machine-policy verify reports an adapter that
// differs from it.
func windowsCursorManagedAdapterMatchesState(state windowsCursorManagedPolicyState, adapter []byte) bool {
	if len(adapter) == 0 || !validWindowsCursorManagedDigest(state.AdapterSHA256) ||
		state.AdapterSHA256 != windowsManagedPolicyDigest(adapter) {
		return false
	}
	hookExecutable := "'" + strings.ReplaceAll(state.HookExecutable, "'", "''") + "'"
	return bytes.Contains(adapter, []byte(hookExecutable))
}

// windowsCursorManagedAdapterRefresh returns the adapter and ownership state
// that bring an active deployment's adapter to this build's template, or
// ok=false when the adapter is already current or belongs to another hook
// executable. Only the adapter body and its recorded digest change; the
// targets and the receipt binding stay as they are (GAP-2467).
func windowsCursorManagedAdapterRefresh(
	artifacts windowsCursorManagedArtifacts,
	hookExecutable string,
) (adapter, state []byte, ok bool, err error) {
	if !artifacts.active ||
		!sameWindowsEnterprisePath(artifacts.parsed.HookExecutable, hookExecutable) {
		return nil, nil, false, nil
	}
	adapter, err = renderWindowsCursorManagedAdapter(artifacts.parsed)
	if err != nil {
		return nil, nil, false, err
	}
	if bytes.Equal(artifacts.adapter.data, adapter) {
		return nil, nil, false, nil
	}
	parsed := artifacts.parsed
	parsed.AdapterSHA256 = windowsManagedPolicyDigest(adapter)
	state, err = windowsCursorManagedStateBody(parsed)
	if err != nil {
		return nil, nil, false, err
	}
	return adapter, state, true, nil
}

// windowsCursorManagedAdapterDriftCandidate returns current with the adapter
// replaced by this build's render and the state digest rebound to it. It is
// for an active deployment whose adapter file was changed in place (GAP-2474)
// or deleted (GAP-2479), so it no longer matches its protected state. The
// state must be the exact canonical body DefenseClaw wrote and must name
// hookExecutable. The caller validates the candidate like any deployment, so
// the adapter body is the only thing that may differ from a valid policy.
func windowsCursorManagedAdapterDriftCandidate(
	current windowsCursorManagedArtifacts,
	hookExecutable string,
) (windowsCursorManagedArtifacts, error) {
	if !current.state.existed {
		return current, errors.New("enterprise hooks: Cursor managed ownership metadata is incomplete")
	}
	var state windowsCursorManagedPolicyState
	if err := json.Unmarshal(current.state.data, &state); err != nil {
		return current, fmt.Errorf("enterprise hooks: parse Cursor managed ownership metadata: %w", err)
	}
	canonical, err := windowsCursorManagedStateBody(state)
	if err != nil {
		return current, err
	}
	if !bytes.Equal(canonical, current.state.data) {
		return current, errors.New("enterprise hooks: Cursor managed ownership metadata is not canonical")
	}
	if !filepath.IsAbs(state.HookExecutable) || !sameWindowsEnterprisePath(state.HookExecutable, hookExecutable) {
		return current, errors.New("enterprise hooks: Cursor managed policy belongs to another hook executable")
	}
	adapter, err := renderWindowsCursorManagedAdapter(state)
	if err != nil {
		return current, err
	}
	state.AdapterSHA256 = windowsManagedPolicyDigest(adapter)
	body, err := windowsCursorManagedStateBody(state)
	if err != nil {
		return current, err
	}
	candidate := current
	candidate.adapter.existed = true
	candidate.adapter.data = adapter
	candidate.state.data = body
	return candidate, nil
}

// RefreshWindowsCursorManagedAdapter rewrites the active Cursor enterprise
// adapter when it is not this build's render: an upgrade changed its
// template (GAP-2467), or the file was changed in place (GAP-2474) or
// deleted (GAP-2479). Per-user
// rows verify against the protected state, so without this an upgrade keeps
// the adapter an earlier release wrote, and a changed adapter fails every
// verify and repair until it is restored. It reports whether it rewrote the
// adapter.
func RefreshWindowsCursorManagedAdapter(hookExecutable string) (bool, error) {
	return refreshWindowsCursorManagedAdapter(hookExecutable, true)
}

// RestoreWindowsCursorManagedAdapter repairs a damaged adapter. On a
// standalone host it rebuilds every guard artifact that is missing or changed,
// the adapter and the hooks.json registration together, from the protected
// state (restoreWindowsCursorManagedGuard). It leaves an earlier release's
// recorded adapter alone, so a lifecycle snapshot still captures it (GAP-1068).
func RestoreWindowsCursorManagedAdapter(hookExecutable string) (bool, error) {
	return refreshWindowsCursorManagedAdapter(hookExecutable, false)
}

// restoreWindowsCursorManagedGuard rebuilds a standalone Cursor machine guard
// from its machine-owned record: the canonical protected state and the private
// rollback receipt it binds. Whichever of the adapter and the hooks.json
// registration is missing or changed is rewritten from that record in one
// locked step, and the complete guard is validated before it returns. Any
// failure undoes every file it wrote, so a repair never stops with a
// half-rebuilt guard. Target enrollment never changes.
//
// hooks.json is shared: administrators and Cursor do not take the DefenseClaw
// lock. The rebuild edits only DefenseClaw's own entries there and keeps every
// other byte (SpliceWindowsCursorEnterpriseHooks). It writes each file with a
// compare-and-swap that publishes only over the file the rebuild read
// (swapWindowsCursorManagedFile). When another writer changed a file in
// between, the newer file is kept, the rebuild undoes its other writes, each
// only over its own bytes, and starts again from what is on disk, up to
// windowsCursorManagedGuardRebuildAttempts times. A hooks.json that is not JSON
// when the rebuild starts cannot carry the guard and is replaced. One that
// another writer leaves not JSON during the rebuild, a save in progress, say,
// is kept, and the rebuild stops.
//
// It writes nothing and reports false when the record does not authenticate:
// Secure Client, no state or receipt, state DefenseClaw did not write, another
// hook executable, or a receipt the state does not bind. A hooks.json that is
// JSON but not a version 1 Cursor hooks document is refused before any write.
// After a concurrent change it reports true, so the caller reads the guard
// again. Callers hold the Cursor transaction lock.
func restoreWindowsCursorManagedGuard(
	current windowsCursorManagedArtifacts,
	hookExecutable string,
) (bool, error) {
	replaceInvalid := true
	for attempt := 1; ; attempt++ {
		rebuilt, err := rebuildWindowsCursorManagedGuardOnce(current, hookExecutable, replaceInvalid)
		if !errors.Is(err, errWindowsCursorManagedConcurrentChange) {
			return rebuilt || (err == nil && attempt > 1), err
		}
		if attempt == windowsCursorManagedGuardRebuildAttempts {
			return false, fmt.Errorf(
				"enterprise hooks: Cursor guard rebuild stopped after %d concurrent changes: %w", attempt, err)
		}
		next, snapshotErr := snapshotWindowsCursorManagedArtifacts()
		if snapshotErr != nil {
			return false, errors.Join(err, snapshotErr)
		}
		if next.hooks.existed != current.hooks.existed || !bytes.Equal(next.hooks.data, current.hooks.data) {
			replaceInvalid = false
		}
		current = next
	}
}

// windowsCursorManagedGuardRebuildAttempts bounds how often a guard rebuild
// or a shared hooks.json write starts again after another writer changed one
// of its files.
const windowsCursorManagedGuardRebuildAttempts = 4

func rebuildWindowsCursorManagedGuardOnce(
	current windowsCursorManagedArtifacts,
	hookExecutable string,
	replaceInvalid bool,
) (bool, error) {
	if !windowsEnterpriseStandaloneProcess() || !current.state.existed || !current.receipt.existed {
		return false, nil
	}
	candidate, err := windowsCursorManagedAdapterDriftCandidate(current, hookExecutable)
	if err != nil {
		return false, nil
	}
	var recorded windowsCursorManagedPolicyState
	if err := json.Unmarshal(current.state.data, &recorded); err != nil {
		return false, nil
	}
	if current.adapter.existed && windowsCursorManagedAdapterMatchesState(recorded, current.adapter.data) {
		// Keep the recorded adapter, also an earlier release's (GAP-1068).
		candidate.adapter, candidate.state = current.adapter, current.state
	}
	if err := json.Unmarshal(candidate.state.data, &candidate.parsed); err != nil {
		return false, nil
	}
	if _, err := validateWindowsCursorManagedReceipt(candidate); err != nil {
		return false, nil
	}
	failMode := cursorManagedPolicyFailMode(candidate.parsed)
	hooks, err := mergeWindowsCursorManagedRebuildHooks(current.hooks, current.adapter.path, failMode, replaceInvalid)
	if err != nil {
		return false, err
	}

	var plan []*windowsCursorManagedRebuildWrite
	if !current.adapter.existed || !bytes.Equal(current.adapter.data, candidate.adapter.data) {
		plan = append(plan, &windowsCursorManagedRebuildWrite{
			preimage: current.adapter, limit: windowsCursorManagedAdapterLimit, data: candidate.adapter.data,
		})
	}
	if !bytes.Equal(current.state.data, candidate.state.data) {
		plan = append(plan, &windowsCursorManagedRebuildWrite{
			preimage: current.state, limit: windowsCursorManagedStateLimit, data: candidate.state.data,
		})
	}
	if !current.hooks.existed || !bytes.Equal(current.hooks.data, hooks) {
		plan = append(plan, &windowsCursorManagedRebuildWrite{
			preimage: current.hooks, limit: windowsCursorManagedHooksLimit, data: hooks, shared: true,
		})
	}
	if len(plan) == 0 {
		return false, nil
	}
	var written []*windowsCursorManagedRebuildWrite
	rollback := func(cause error) error {
		for index := len(written) - 1; index >= 0; index-- {
			cause = errors.Join(cause, written[index].undo())
		}
		return cause
	}
	for _, item := range plan {
		windowsCursorManagedGuardRebuildBeforeWrite(item.preimage.path)
		swapped, err := item.write()
		if swapped {
			written = append(written, item)
		}
		if err != nil {
			return false, rollback(err)
		}
	}
	repaired, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		return false, rollback(err)
	}
	validated, err := validateWindowsCursorManagedArtifacts(repaired)
	if err == nil && !validated.active {
		err = errors.New("enterprise hooks: rebuilt Cursor machine guard is not active")
	}
	if err != nil {
		for _, item := range written {
			if raced := item.changedSinceWrite(); raced != nil {
				err = errors.Join(err, raced)
				break
			}
		}
		return false, rollback(err)
	}
	return true, nil
}

// windowsCursorManagedRebuildWrite is one file a guard rebuild replaces.
type windowsCursorManagedRebuildWrite struct {
	// preimage is the file the rebuild read and, once written, the file the
	// write replaced; metadata is that file's.
	preimage windowsManagedFileSnapshot
	metadata windowsCursorManagedFileMetadata
	limit    int
	data     []byte
	// shared marks hooks.json, which keeps the replaced file's security
	// descriptor and attributes. The adapter and state get DefenseClaw's.
	shared bool
}

// write replaces the file with data, only while it still holds the preimage,
// and reports whether it did. A different file is newer and is kept: the error
// wraps errWindowsCursorManagedConcurrentChange. So does a file that changes
// again before it is read back.
func (item *windowsCursorManagedRebuildWrite) write() (bool, error) {
	result, err := windowsCursorManagedFileSwap(windowsCursorManagedSwap{
		path: item.preimage.path, expect: item.preimage, data: item.data, limit: item.limit,
		keepReplacedMetadata: item.shared,
	})
	if !result.swapped {
		return false, err
	}
	item.metadata = result.replacedMetadata
	if err != nil {
		return true, err
	}
	return true, item.changedSinceWrite()
}

// changedSinceWrite reports a concurrent change when the file no longer holds
// what the rebuild wrote.
func (item *windowsCursorManagedRebuildWrite) changedSinceWrite() error {
	now, err := snapshotWindowsManagedFileWithLimit(item.preimage.path, item.limit)
	if err != nil {
		return err
	}
	if !now.existed || !bytes.Equal(now.data, item.data) {
		return windowsCursorManagedConcurrentChange(item.preimage.path)
	}
	return nil
}

// undo puts the preimage back, but only over the bytes the rebuild wrote: the
// put-back is one compare-and-swap under a handle no other process can write
// through. A file another writer saved after the rebuild wrote is newer than
// the preimage and is kept; the error then wraps
// errWindowsCursorManagedConcurrentChange.
func (item *windowsCursorManagedRebuildWrite) undo() error {
	path := item.preimage.path
	if !item.preimage.existed {
		_, err := removeWindowsCursorManagedFileIfUnchanged(path, item.data, item.limit)
		return err
	}
	_, err := windowsCursorManagedFileSwap(windowsCursorManagedSwap{
		path: path, expect: windowsManagedFileSnapshot{path: path, existed: true, data: item.data},
		data: item.preimage.data, limit: item.limit, metadata: &item.metadata,
	})
	if err != nil && !errors.Is(err, errWindowsCursorManagedConcurrentChange) {
		return fmt.Errorf("enterprise hooks: restore Cursor preimage %s: %w", path, err)
	}
	return err
}

// mergeWindowsCursorManagedRebuildHooks renders hooks.json with the guard's
// registration spliced into the snapshot: only DefenseClaw's entries change,
// and every other entry keeps its bytes. A missing file starts empty. A file
// that is not JSON cannot carry the guard: it is replaced when replaceInvalid
// is set, and refused otherwise (another writer's save in progress is never
// discarded).
func mergeWindowsCursorManagedRebuildHooks(
	snapshot windowsManagedFileSnapshot,
	adapterPath string,
	failMode string,
	replaceInvalid bool,
) ([]byte, error) {
	base := []byte("{}\n")
	if snapshot.existed {
		if err := windowsManagedPolicyFileTrustCheck(snapshot.path); err != nil {
			return nil, fmt.Errorf("enterprise hooks: untrusted Cursor enterprise artifact %s: %w", snapshot.path, err)
		}
		base = snapshot.data
	}
	hooks, err := connector.SpliceWindowsCursorEnterpriseHooks(base, adapterPath, failMode)
	if err != nil && replaceInvalid && snapshot.existed && !json.Valid(snapshot.data) {
		fmt.Fprintf(os.Stderr,
			"[enterprise-hooks] replacing %s, which is not JSON, to restore the Cursor machine guard\n",
			snapshot.path)
		hooks, err = connector.SpliceWindowsCursorEnterpriseHooks([]byte("{}\n"), adapterPath, failMode)
	}
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: rebuild Cursor hooks.json registration: %w", err)
	}
	if len(hooks) > windowsCursorManagedHooksLimit {
		return nil, fmt.Errorf("enterprise hooks: rebuilt Cursor hooks.json exceeds %d bytes", windowsCursorManagedHooksLimit)
	}
	return hooks, nil
}

func refreshWindowsCursorManagedAdapter(hookExecutable string, upgradeTemplate bool) (bool, error) {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return false, err
	}
	hookExecutable = filepath.Clean(hookExecutable)
	refreshed := false
	err := withWindowsCursorManagedTransaction(func() error {
		current, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		artifacts, err := validateWindowsCursorManagedArtifactsReclaimingOrphans(current)
		if err != nil {
			rebuilt, rebuildErr := restoreWindowsCursorManagedGuard(current, hookExecutable)
			if rebuildErr != nil {
				return fmt.Errorf("rebuild Cursor machine guard: %w", errors.Join(err, rebuildErr))
			}
			if rebuilt {
				refreshed = true
				current, err = snapshotWindowsCursorManagedArtifacts()
				if err != nil {
					return err
				}
				artifacts, err = validateWindowsCursorManagedArtifacts(current)
			}
		}
		if err != nil {
			candidate, candidateErr := windowsCursorManagedAdapterDriftCandidate(current, hookExecutable)
			if candidateErr != nil {
				return err
			}
			if !current.adapter.existed {
				// A deleted adapter (GAP-2479): the trust checks read the
				// file, so write this build's render first, and remove it
				// again unless the deployment then validates.
				if writeErr := windowsManagedPolicyWriter(current.adapter.path, candidate.adapter.data, true); writeErr != nil {
					return fmt.Errorf("%v (Cursor adapter restore failed: %v)", err, writeErr)
				}
			}
			if artifacts, candidateErr = validateWindowsCursorManagedArtifacts(candidate); candidateErr != nil ||
				!artifacts.active {
				if !current.adapter.existed {
					if removeErr := restoreWindowsCursorManagedFile(current.adapter, current.adapterMetadata); removeErr != nil {
						return fmt.Errorf("%v (Cursor adapter rollback failed: %v)", err, removeErr)
					}
				}
				return err
			}
			// Write over, and roll back to, the adapter that is on disk.
			artifacts.adapter = current.adapter
		} else if !upgradeTemplate {
			return nil
		}
		adapter, state, ok, err := windowsCursorManagedAdapterRefresh(artifacts, hookExecutable)
		if err != nil || !ok {
			return err
		}
		if err := windowsManagedPolicyWriter(artifacts.adapter.path, adapter, true); err != nil {
			return err
		}
		if err := windowsManagedPolicyWriter(artifacts.state.path, state, true); err != nil {
			if restoreErr := restoreWindowsCursorManagedFile(artifacts.adapter, artifacts.adapterMetadata); restoreErr != nil {
				return fmt.Errorf("%v (Cursor adapter rollback failed: %v)", err, restoreErr)
			}
			return err
		}
		refreshed = true
		return nil
	})
	return refreshed, err
}

func validWindowsCursorManagedDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func cursorManagedPolicyFailMode(state windowsCursorManagedPolicyState) string {
	// Pre-upgrade protected state omitted the mode and always rendered closed.
	// Otherwise the adapter runs the administrator's mode (owner decision
	// 2026-10-20; under Secure Client #1163).
	if state.HookFailMode == "" {
		return "closed"
	}
	return canonicalHookFailMode(state.HookFailMode)
}

// Legacy state is intentionally rendered byte-for-byte until reconciliation.
// New state binds every enrolled SID to its own adapter fallback policy.
func renderWindowsCursorManagedAdapter(state windowsCursorManagedPolicyState) ([]byte, error) {
	if state.TargetFailModes == nil {
		return connector.RenderWindowsCursorEnterpriseAdapter(state.HookExecutable, cursorManagedPolicyFailMode(state))
	}
	if len(state.TargetFailModes) != len(state.Targets) || len(state.Targets) == 0 {
		return nil, errors.New("enterprise hooks: Cursor target mode map does not match enrollment")
	}
	aggregate := "open"
	for _, target := range state.Targets {
		mode, ok := state.TargetFailModes[target.SID]
		if !ok || (mode != "open" && mode != "closed") {
			return nil, errors.New("enterprise hooks: Cursor target delivery mode is invalid")
		}
		if mode == "closed" {
			aggregate = "closed"
		}
	}
	if state.HookFailMode != aggregate {
		return nil, errors.New("enterprise hooks: Cursor shared failClosed flag does not match target modes")
	}
	return connector.RenderWindowsCursorEnterpriseAdapterForTargets(state.HookExecutable, state.TargetFailModes)
}

func cursorManagedTargetFailMode(state windowsCursorManagedPolicyState, sid string) string {
	if state.TargetFailModes == nil {
		return cursorManagedPolicyFailMode(state)
	}
	return state.TargetFailModes[sid]
}

// Copy on write: callers retain the authenticated preimage for rollback.
func cursorManagedTargetModes(state windowsCursorManagedPolicyState) map[string]string {
	modes := make(map[string]string, len(state.Targets))
	for _, target := range state.Targets {
		modes[target.SID] = cursorManagedTargetFailMode(state, target.SID)
	}
	return modes
}

func cursorManagedAggregateFailMode(modes map[string]string) string {
	for _, mode := range modes {
		if mode != "open" {
			return "closed"
		}
	}
	return "open"
}

func cursorManagedSetTargetFailMode(state *windowsCursorManagedPolicyState, sid, mode string) {
	state.TargetFailModes = cursorManagedTargetModes(*state)
	state.TargetFailModes[sid] = canonicalHookFailMode(mode)
	state.HookFailMode = cursorManagedAggregateFailMode(state.TargetFailModes)
}

func cursorManagedNarrowState(state windowsCursorManagedPolicyState, targets []WindowsCursorManagedRuntimeTarget) (windowsCursorManagedPolicyState, error) {
	if len(targets) == 0 {
		state.Targets = []WindowsCursorManagedRuntimeTarget{}
		state.TargetFailModes = nil
		state.HookFailMode = "closed"
		return state, nil
	}
	modes := make(map[string]string, len(targets))
	for _, target := range targets {
		mode, ok := state.TargetFailModes[target.SID]
		if !ok {
			return state, errors.New("enterprise hooks: cannot publish a Cursor target without an enrolled delivery mode")
		}
		found := false
		for _, enrolled := range state.Targets {
			if enrolled == target {
				found = true
				break
			}
		}
		if !found {
			return state, errors.New("enterprise hooks: cannot replace a Cursor enrollment without installing its runtime")
		}
		modes[target.SID] = mode
	}
	state.Targets = targets
	state.TargetFailModes = modes
	state.HookFailMode = cursorManagedAggregateFailMode(modes)
	return state, nil
}

func validateWindowsCursorPrivateReceiptMetadata(
	metadata windowsCursorManagedFileMetadata,
) error {
	descriptor, err := windows.SecurityDescriptorFromString(metadata.securityDescriptor)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("enterprise hooks: Cursor rollback receipt has an invalid security descriptor")
	}
	expectedOwner, err := windowsManagedPolicyOwnerSID()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(expectedOwner) {
		return errors.New("enterprise hooks: Cursor rollback receipt has an unexpected owner")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("enterprise hooks: Cursor rollback receipt DACL is not protected")
	}
	// DACL's boolean result is "defaulted", not "present". A missing DACL is
	// returned as an error, while a nil DACL remains fully permissive and must
	// still be rejected here.
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("enterprise hooks: Cursor rollback receipt has no protected DACL")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	coverage := map[string]bool{
		expectedOwner.String(): false,
		system.String():        false,
	}
	fullMasks := map[windows.ACCESS_MASK]bool{
		windows.GENERIC_ALL: true,
		mapWindowsUserPathGenericMask(windows.GENERIC_ALL): true,
	}
	if int(dacl.AceCount) != len(coverage) {
		return errors.New("enterprise hooks: Cursor rollback receipt DACL grants unexpected access")
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("enterprise hooks: inspect Cursor rollback receipt ACE %d: %w", index, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != 0 || !fullMasks[ace.Mask] {
			return errors.New("enterprise hooks: Cursor rollback receipt has a noncanonical access rule")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil {
			return errors.New("enterprise hooks: Cursor rollback receipt has an invalid access principal")
		}
		key := sid.String()
		seen, ok := coverage[key]
		if !ok || seen {
			return errors.New("enterprise hooks: Cursor rollback receipt grants an unexpected principal access")
		}
		coverage[key] = true
	}
	for _, covered := range coverage {
		if !covered {
			return errors.New("enterprise hooks: Cursor rollback receipt lacks required private access")
		}
	}
	return nil
}

func canonicalWindowsCursorManagedTargets(
	raw []WindowsCursorManagedRuntimeTarget,
	validateProfiles bool,
) ([]WindowsCursorManagedRuntimeTarget, error) {
	targets := make([]WindowsCursorManagedRuntimeTarget, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		sid, err := validateWindowsEnterpriseTargetSID(item.SID)
		if err != nil {
			return nil, err
		}
		dataDir := strings.TrimSpace(item.DataDir)
		if dataDir == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir ||
			!strings.EqualFold(filepath.Base(dataDir), ".defenseclaw") {
			return nil, fmt.Errorf("enterprise hooks: Cursor target %s has noncanonical data dir %q", sid, item.DataDir)
		}
		key := strings.ToUpper(sid.String())
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("enterprise hooks: duplicate Cursor target SID %s", sid)
		}
		seen[key] = struct{}{}
		if validateProfiles {
			home := filepath.Dir(dataDir)
			verifiedHome, verifiedSID, err := validateWindowsEnterpriseHome(home, sid.String())
			if err != nil {
				return nil, err
			}
			if !sameWindowsEnterprisePath(home, verifiedHome) || !verifiedSID.Equals(sid) {
				return nil, fmt.Errorf("enterprise hooks: Cursor target %s profile identity changed", sid)
			}
		}
		targets = append(targets, WindowsCursorManagedRuntimeTarget{SID: sid.String(), DataDir: dataDir})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].SID < targets[j].SID })
	return targets, nil
}

func windowsCursorManagedStateBody(state windowsCursorManagedPolicyState) ([]byte, error) {
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	if len(body) > windowsCursorManagedStateLimit {
		return nil, fmt.Errorf("enterprise hooks: Cursor managed state exceeds %d bytes", windowsCursorManagedStateLimit)
	}
	return body, nil
}

func windowsCursorManagedReceiptBody(receipt windowsCursorManagedPolicyReceipt) ([]byte, error) {
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	if len(body) > windowsCursorManagedReceiptLimit {
		return nil, fmt.Errorf("enterprise hooks: Cursor managed receipt exceeds %d bytes", windowsCursorManagedReceiptLimit)
	}
	return body, nil
}

func installWindowsCursorManagedPolicy(
	opts connector.SetupOpts,
	targetSID *windows.SID,
	dataDir string,
) (func() error, error) {
	targets := []WindowsCursorManagedRuntimeTarget{}
	if targetSID != nil {
		var err error
		targets, err = canonicalWindowsCursorManagedTargets([]WindowsCursorManagedRuntimeTarget{{
			SID: targetSID.String(), DataDir: dataDir,
		}}, true)
		if err != nil {
			return nil, err
		}
	} else if !windowsEnterpriseStandaloneProcess() {
		return nil, errors.New("enterprise hooks: Cursor target SID is required outside standalone mode")
	}
	var rollback func() error
	install := func() error {
		before, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		current, err := validateWindowsCursorManagedArtifactsReclaimingOrphans(before)
		if err != nil {
			return err
		}
		if !windowsCursorManagedFileSnapshotEqual(current.hooks, current.hooksMetadata, before.hooks, before.hooksMetadata) {
			// An orphan reclaim rewrote hooks.json. The cleaned file is the
			// preimage: the receipt's original config, the merge base and the
			// concurrent-change checks below must all see it, not the stale
			// pre-reclaim bytes.
			before = current
		}
		gateway, err := connector.NormalizeWindowsManagedGatewayAddr(opts.APIAddr)
		if err != nil {
			return err
		}
		service := os.Getenv(connector.WindowsGatewayServiceNameEnv)
		if err := connector.ValidateWindowsManagedGatewayServiceName(service); err != nil {
			return err
		}
		if before.hooks.existed && !current.active {
			if err := windowsManagedPolicyFileTrustCheck(before.hooks.path); err != nil {
				return fmt.Errorf("enterprise hooks: pre-existing Cursor enterprise config is not trusted: %w", err)
			}
		}

		state := current.parsed
		receipt := current.parsedReceipt
		if !current.active {
			state = windowsCursorManagedPolicyState{SchemaVersion: 1}
			receipt = windowsCursorManagedPolicyReceipt{
				SchemaVersion:                    1,
				ConfigPreexisting:                before.hooks.existed,
				ConfigOriginal:                   append([]byte(nil), before.hooks.data...),
				ConfigOriginalSecurityDescriptor: before.hooksMetadata.securityDescriptor,
				ConfigOriginalAttributes:         before.hooksMetadata.attributes,
			}
			if before.hooks.existed {
				receipt.ConfigOriginalSHA256 = windowsManagedPolicyDigest(before.hooks.data)
			}
		}
		if current.active && (!sameWindowsEnterprisePath(state.HookExecutable, opts.HookExecutable) ||
			state.GatewayAddr != gateway || state.GatewayServiceName != service) {
			return errors.New("enterprise hooks: Cursor machine identity differs from the active protected deployment")
		}
		if targetSID == nil && current.active {
			return nil
		}
		state.SchemaVersion = 1
		if targetSID != nil {
			cursorManagedSetTargetFailMode(&state, targets[0].SID, opts.HookFailMode)
		} else {
			state.HookFailMode = "closed"
			state.TargetFailModes = nil
		}
		state.HookExecutable = filepath.Clean(opts.HookExecutable)
		state.GatewayAddr = gateway
		state.GatewayServiceName = service
		next := append([]WindowsCursorManagedRuntimeTarget(nil), state.Targets...)
		for _, target := range targets {
			filtered := next[:0]
			for _, existing := range next {
				if !strings.EqualFold(existing.SID, target.SID) {
					filtered = append(filtered, existing)
				}
			}
			next = append(filtered, target)
		}
		state.Targets, err = canonicalWindowsCursorManagedTargets(next, true)
		if err != nil {
			return err
		}
		adapterBody, err := renderWindowsCursorManagedAdapter(state)
		if err != nil {
			return err
		}
		state.AdapterSHA256 = windowsManagedPolicyDigest(adapterBody)
		// hooks.json is shared: the registration is merged into whatever file
		// is there when it is published (publishWindowsCursorManagedHooks).
		renderHooks := func(base windowsManagedFileSnapshot) (windowsCursorManagedHooksEdit, error) {
			if !current.active && (base.existed != before.hooks.existed || !bytes.Equal(base.data, before.hooks.data)) {
				// The receipt records the file this install read as the
				// original configuration.
				return windowsCursorManagedHooksEdit{}, windowsCursorManagedConcurrentChange(base.path)
			}
			data := base.data
			if !base.existed {
				data = []byte("{}\n")
			}
			hooks, err := connector.MergeWindowsCursorEnterpriseHooks(data, before.adapter.path, state.HookFailMode)
			return windowsCursorManagedHooksEdit{data: hooks}, err
		}
		if _, err := renderHooks(before.hooks); err != nil {
			return err
		}
		receiptBody, err := windowsCursorManagedReceiptBody(receipt)
		if err != nil {
			return err
		}
		state.ReceiptSHA256 = windowsManagedPolicyDigest(receiptBody)
		stateBody, err := windowsCursorManagedStateBody(state)
		if err != nil {
			return err
		}
		var activation windowsCursorManagedHooksWrite
		restore := func() error {
			var failures []string
			for _, item := range []struct {
				snapshot windowsManagedFileSnapshot
				metadata windowsCursorManagedFileMetadata
			}{
				{before.adapter, before.adapterMetadata},
				{before.receipt, before.receiptMetadata},
				{before.state, before.stateMetadata},
			} {
				if err := restoreWindowsCursorManagedFile(item.snapshot, item.metadata); err != nil {
					failures = append(failures, err.Error())
				}
			}
			// hooks.json is undone only over the activation's own bytes. A save
			// an administrator made since is newer and is kept.
			if err := activation.undo(); errors.Is(err, errWindowsCursorManagedConcurrentChange) {
				nowHooks, readErr := snapshotWindowsManagedFileWithLimit(before.hooks.path, windowsCursorManagedHooksLimit)
				switch {
				case readErr != nil:
					failures = append(failures, readErr.Error())
				case current.active:
					// Keep it only while the prior active policy remains callable.
					if verifyErr := connector.VerifyWindowsCursorEnterpriseHooksForMigration(
						nowHooks.data,
						before.adapter.path,
						cursorManagedPolicyFailMode(current.parsed),
					); verifyErr != nil {
						failures = append(failures, fmt.Sprintf("concurrent Cursor config invalidated the restored policy: %v", verifyErr))
					}
				default:
					// A fresh-install rollback must not leave the newer hooks.json
					// pointing at an adapter/state it just removed.
					if _, removeErr := publishWindowsCursorManagedHooks(nowHooks, func(base windowsManagedFileSnapshot) (windowsCursorManagedHooksEdit, error) {
						if !base.existed {
							return windowsCursorManagedHooksEdit{remove: true}, nil
						}
						cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(base.data, before.adapter.path)
						return windowsCursorManagedHooksEdit{data: cleaned}, err
					}); removeErr != nil {
						failures = append(failures, fmt.Sprintf("remove DefenseClaw entries from concurrent Cursor config: %v", removeErr))
					}
					if !before.adapter.existed {
						if tombstoneErr := windowsManagedPolicyWriter(
							before.adapter.path,
							windowsCursorManagedTombstone(),
							true,
						); tombstoneErr != nil {
							failures = append(failures, tombstoneErr.Error())
						}
					}
				}
			} else if err != nil {
				failures = append(failures, err.Error())
			}
			if len(failures) > 0 {
				return errors.New(strings.Join(failures, "; "))
			}
			return nil
		}
		failMutation := func(cause error) error {
			if rollbackErr := restore(); rollbackErr != nil {
				return fmt.Errorf("%v (Cursor policy rollback failed: %v)", cause, rollbackErr)
			}
			return cause
		}
		if err := windowsManagedPolicyWriter(before.adapter.path, adapterBody, true); err != nil {
			return failMutation(err)
		}
		if err := writeWindowsCursorPrivateReceipt(before.receipt.path, receiptBody); err != nil {
			return failMutation(err)
		}
		if err := windowsManagedPolicyWriter(before.state.path, stateBody, true); err != nil {
			return failMutation(err)
		}
		// Activation is last: Cursor cannot invoke the command before its adapter
		// and SID registry are durable and protected.
		if activation, err = publishWindowsCursorManagedHooks(before.hooks, renderHooks); err != nil {
			return failMutation(err)
		}
		installed, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return failMutation(err)
		}
		installed, err = validateWindowsCursorManagedArtifacts(installed)
		if err != nil || !installed.active {
			if err == nil {
				err = errors.New("Cursor enterprise policy did not become active")
			}
			return failMutation(err)
		}
		if err := connector.VerifyWindowsCursorEnterpriseHooks(installed.hooks.data, installed.adapter.path, cursorManagedPolicyFailMode(installed.parsed)); err != nil {
			return failMutation(fmt.Errorf("enterprise hooks: installed Cursor hook command is not current: %w", err))
		}
		rollback = func() error {
			return withWindowsCursorManagedTransaction(func() error {
				now, err := snapshotWindowsCursorManagedArtifacts()
				if err != nil {
					return err
				}
				if !windowsCursorManagedFileSnapshotEqual(now.hooks, now.hooksMetadata, installed.hooks, installed.hooksMetadata) ||
					!windowsCursorManagedFileSnapshotEqual(now.adapter, now.adapterMetadata, installed.adapter, installed.adapterMetadata) ||
					!windowsCursorManagedFileSnapshotEqual(now.state, now.stateMetadata, installed.state, installed.stateMetadata) ||
					!windowsCursorManagedFileSnapshotEqual(now.receipt, now.receiptMetadata, installed.receipt, installed.receiptMetadata) {
					return errors.New("enterprise hooks: refusing Cursor rollback after a concurrent policy change")
				}
				return restore()
			})
		}
		return nil
	}
	// A hooks.json save during a fresh install stops it, because its receipt
	// records the file it read: start again from the newer file.
	for attempt := 1; ; attempt++ {
		err := withWindowsCursorManagedTransaction(install)
		if !errors.Is(err, errWindowsCursorManagedConcurrentChange) || attempt == windowsCursorManagedGuardRebuildAttempts {
			return rollback, err
		}
	}
}

func windowsCursorManagedTombstone() []byte {
	return []byte("# defenseclaw-managed-cursor-tombstone v1\r\n[Console]::Out.Write('{\"continue\":true}')\r\nexit 0\r\n")
}

// PurgeWindowsCursorManagedTombstone removes, for the standalone uninstall
// with purge, the allow-only Cursor adapter tombstone the teardown left for
// Cursor processes that were still running, and then the Cursor transaction
// lock, so the delete-everything option leaves no DefenseClaw file in
// ProgramData\Cursor (GAP-1567). Only the exact tombstone goes; ownership
// state, a receipt or an active adapter fail. A missing folder is not an
// error and is not created.
func PurgeWindowsCursorManagedTombstone() error {
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
	present := false
	for _, path := range []string{paths.Adapter, paths.Lock} {
		if _, statErr := os.Lstat(path); statErr == nil {
			present = true
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("enterprise hooks: inspect %s: %w", path, statErr)
		}
	}
	if !present {
		return nil
	}
	return withWindowsCursorManagedTransaction(purgeWindowsCursorManagedTombstoneUnlocked)
}

func purgeWindowsCursorManagedTombstoneUnlocked() error {
	artifacts, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		return err
	}
	if artifacts.state.existed || artifacts.receipt.existed {
		return errors.New("enterprise hooks: Cursor managed ownership state remains, so the Cursor hook tombstone stays")
	}
	if !artifacts.adapter.existed {
		return nil
	}
	if !bytes.Equal(artifacts.adapter.data, windowsCursorManagedTombstone()) {
		return fmt.Errorf("enterprise hooks: %s is not the DefenseClaw Cursor hook tombstone, so it stays", artifacts.adapter.path)
	}
	if err := os.Remove(artifacts.adapter.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("enterprise hooks: remove the Cursor hook tombstone: %w", err)
	}
	return nil
}

func removeWindowsCursorManagedPolicyTarget(targetSID *windows.SID) error {
	if targetSID == nil {
		return errors.New("enterprise hooks: Cursor target SID is required")
	}
	return withWindowsCursorManagedTransaction(func() error {
		current, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		artifacts, err := validateWindowsCursorManagedArtifactsReclaimingOrphans(current)
		if err != nil || !artifacts.active {
			return err
		}
		remaining := make([]WindowsCursorManagedRuntimeTarget, 0, len(artifacts.parsed.Targets))
		for _, target := range artifacts.parsed.Targets {
			if !strings.EqualFold(target.SID, targetSID.String()) {
				remaining = append(remaining, target)
			}
		}
		return publishWindowsCursorManagedPolicyTargetsUnlocked(artifacts, remaining)
	})
}

// ReadWindowsCursorManagedPolicyTargets returns the protected exact SID to
// data-directory registry and never consults target-owned runtime files.
func ReadWindowsCursorManagedPolicyTargets() ([]WindowsCursorManagedRuntimeTarget, bool, error) {
	artifacts, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		return nil, false, err
	}
	artifacts, err = validateWindowsCursorManagedArtifacts(artifacts)
	if err != nil {
		return nil, true, err
	}
	if !artifacts.active {
		return []WindowsCursorManagedRuntimeTarget{}, false, nil
	}
	return append([]WindowsCursorManagedRuntimeTarget(nil), artifacts.parsed.Targets...), true, nil
}

// PublishWindowsCursorManagedPolicyTargets narrows or replaces the active
// protected registry after every per-user runtime has been independently
// reconciled. On standalone hosts an empty set retains a closed machine hook.
// Secure Client retains its previous empty-set teardown behavior.
func PublishWindowsCursorManagedPolicyTargets(
	raw []WindowsCursorManagedRuntimeTarget,
) error {
	targets, err := canonicalWindowsCursorManagedTargets(raw, true)
	if err != nil {
		return err
	}
	return withWindowsCursorManagedTransaction(func() error {
		currentArtifacts, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		artifacts, err := validateWindowsCursorManagedArtifactsReclaimingOrphans(currentArtifacts)
		if err != nil {
			return err
		}
		if !artifacts.active {
			if len(targets) == 0 {
				return nil
			}
			return errors.New("enterprise hooks: Cursor policy is absent after target runtime installation")
		}
		return publishWindowsCursorManagedPolicyTargetsUnlocked(artifacts, targets)
	})
}

// EnsureWindowsStandaloneCursorManagedPolicy installs the machine hook even
// when there is no enrolled Cursor account. The adapter and protected empty
// registry make every account fail the enrollment check until authorized.
func EnsureWindowsStandaloneCursorManagedPolicy(setup connector.SetupOpts) error {
	if !windowsEnterpriseStandaloneProcess() {
		return errors.New("enterprise hooks: empty-enrollment Cursor policy is standalone-only")
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	if err := windowsEnterpriseHookTrustCheck(setup.HookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor machine hook executable is untrusted: %w", err)
	}
	setup.ManagedEnterprise = true
	setup.HookFailMode = "closed"
	_, err := installWindowsCursorManagedPolicy(setup, nil, "")
	return err
}

// DeactivateWindowsCursorManagedPolicy removes a machine hook after the
// administrator removes Cursor from the protected connector configuration.
func DeactivateWindowsCursorManagedPolicy() error {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	return withWindowsCursorManagedTransaction(func() error {
		current, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		artifacts, err := validateWindowsCursorManagedArtifactsReclaimingOrphans(current)
		if err != nil || !artifacts.active {
			return err
		}
		return deactivateWindowsCursorManagedPolicyUnlocked(artifacts)
	})
}

func publishWindowsCursorManagedPolicyTargetsUnlocked(
	artifacts windowsCursorManagedArtifacts,
	targets []WindowsCursorManagedRuntimeTarget,
) error {
	if len(targets) > 0 {
		if artifacts.parsed.TargetFailModes != nil {
			return narrowWindowsCursorManagedTargetModes(artifacts, targets)
		}
		artifacts.parsed.Targets = targets
		body, err := windowsCursorManagedStateBody(artifacts.parsed)
		if err != nil {
			return err
		}
		return windowsManagedPolicyWriter(artifacts.state.path, body, true)
	}
	if windowsEnterpriseStandaloneProcess() {
		return narrowWindowsCursorManagedTargetModes(artifacts, targets)
	}
	return deactivateWindowsCursorManagedPolicyUnlocked(artifacts)
}

// Revocation also narrows the executable map, not just the enrollment file.
// All changed protected artifacts roll back together on publication failure.
func narrowWindowsCursorManagedTargetModes(artifacts windowsCursorManagedArtifacts, targets []WindowsCursorManagedRuntimeTarget) error {
	state, err := cursorManagedNarrowState(artifacts.parsed, targets)
	if err != nil {
		return err
	}
	adapter, err := renderWindowsCursorManagedAdapter(state)
	if err != nil {
		return err
	}
	state.AdapterSHA256 = windowsManagedPolicyDigest(adapter)
	body, err := windowsCursorManagedStateBody(state)
	if err != nil {
		return err
	}
	// hooks.json is shared: the registration is merged into whatever file is
	// there when it is published (publishWindowsCursorManagedHooks).
	renderHooks := func(base windowsManagedFileSnapshot) (windowsCursorManagedHooksEdit, error) {
		data := base.data
		if !base.existed {
			data = []byte("{}\n")
		}
		hooks, err := connector.MergeWindowsCursorEnterpriseHooks(data, artifacts.adapter.path, state.HookFailMode)
		return windowsCursorManagedHooksEdit{data: hooks}, err
	}
	if _, err := renderHooks(artifacts.hooks); err != nil {
		return err
	}
	var published windowsCursorManagedHooksWrite
	rollback := func(cause error) error {
		var failures []error
		for _, item := range []struct {
			snapshot windowsManagedFileSnapshot
			metadata windowsCursorManagedFileMetadata
		}{
			{artifacts.adapter, artifacts.adapterMetadata}, {artifacts.state, artifacts.stateMetadata},
		} {
			failures = append(failures, restoreWindowsCursorManagedFile(item.snapshot, item.metadata))
		}
		// hooks.json is undone only over the publication's own bytes. An
		// administrator's newer save is kept while the restored policy stays
		// callable.
		if err := published.undo(); errors.Is(err, errWindowsCursorManagedConcurrentChange) {
			current, readErr := snapshotWindowsManagedFileWithLimit(artifacts.hooks.path, windowsCursorManagedHooksLimit)
			if readErr != nil {
				failures = append(failures, readErr)
			} else {
				failures = append(failures, connector.VerifyWindowsCursorEnterpriseHooksForMigration(current.data, artifacts.adapter.path, artifacts.parsed.HookFailMode))
			}
		} else {
			failures = append(failures, err)
		}
		return errors.Join(append([]error{cause}, failures...)...)
	}
	if err := windowsManagedPolicyWriter(artifacts.adapter.path, adapter, true); err != nil {
		return rollback(err)
	}
	if err := windowsManagedPolicyWriter(artifacts.state.path, body, true); err != nil {
		return rollback(err)
	}
	if published, err = publishWindowsCursorManagedHooks(artifacts.hooks, renderHooks); err != nil {
		return rollback(err)
	}
	installed, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		return rollback(err)
	}
	installed, err = validateWindowsCursorManagedArtifacts(installed)
	if err != nil {
		return rollback(err)
	}
	if !installed.active {
		return rollback(errors.New("enterprise hooks: Cursor target publication did not remain active"))
	}
	return nil
}

func deactivateWindowsCursorManagedPolicyUnlocked(artifacts windowsCursorManagedArtifacts) error {
	// hooks.json is shared: DefenseClaw's entries are removed from whatever
	// file is there when it is published (publishWindowsCursorManagedHooks).
	renderHooks := func(base windowsManagedFileSnapshot) (windowsCursorManagedHooksEdit, error) {
		if !base.existed {
			return windowsCursorManagedHooksEdit{remove: true}, nil
		}
		cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(base.data, artifacts.adapter.path)
		if err != nil {
			return windowsCursorManagedHooksEdit{}, err
		}
		receipt := artifacts.parsedReceipt
		if receipt.ConfigPreexisting && connector.WindowsCursorEnterpriseHooksOwnedRemainderEqual(cleaned, receipt.ConfigOriginal) {
			return windowsCursorManagedHooksEdit{
				data: append([]byte(nil), receipt.ConfigOriginal...),
				metadata: &windowsCursorManagedFileMetadata{
					securityDescriptor: receipt.ConfigOriginalSecurityDescriptor,
					attributes:         receipt.ConfigOriginalAttributes,
				},
			}, nil
		}
		if !receipt.ConfigPreexisting && connector.WindowsCursorEnterpriseHooksEmpty(cleaned) {
			return windowsCursorManagedHooksEdit{remove: true}, nil
		}
		return windowsCursorManagedHooksEdit{data: cleaned}, nil
	}
	if _, err := renderHooks(artifacts.hooks); err != nil {
		return err
	}
	var published windowsCursorManagedHooksWrite
	rollback := func(cause error) error {
		var failures []string
		for _, item := range []struct {
			snapshot windowsManagedFileSnapshot
			metadata windowsCursorManagedFileMetadata
		}{
			{artifacts.adapter, artifacts.adapterMetadata},
			{artifacts.receipt, artifacts.receiptMetadata},
			{artifacts.state, artifacts.stateMetadata},
		} {
			if err := restoreWindowsCursorManagedFile(item.snapshot, item.metadata); err != nil {
				failures = append(failures, err.Error())
			}
		}
		// hooks.json is undone only over the teardown's own bytes: a save an
		// administrator made since is newer and is kept.
		if err := published.undo(); err != nil {
			failures = append(failures, err.Error())
		}
		if len(failures) != 0 {
			return fmt.Errorf("%v (Cursor teardown rollback failed: %s)", cause, strings.Join(failures, "; "))
		}
		return cause
	}
	var err error
	if published, err = publishWindowsCursorManagedHooks(artifacts.hooks, renderHooks); err != nil {
		return rollback(err)
	}
	// Cached Cursor processes may retain the old command after hooks.json is
	// removed. Keep a credential-free allow-only adapter until the next install.
	if err := windowsManagedPolicyWriter(artifacts.adapter.path, windowsCursorManagedTombstone(), true); err != nil {
		return rollback(err)
	}
	if err := os.Remove(artifacts.state.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return rollback(err)
	}
	if err := os.Remove(artifacts.receipt.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return rollback(err)
	}
	if err := VerifyWindowsCursorManagedPolicyTeardown(); err != nil {
		return rollback(err)
	}
	return nil
}

func resolveWindowsCursorManagedPolicyTarget() (windowsCursorManagedPolicyTarget, error) {
	var result windowsCursorManagedPolicyTarget
	artifacts, err := snapshotWindowsCursorManagedPublicArtifacts()
	if err != nil {
		return result, err
	}
	artifacts, err = validateWindowsCursorManagedPublicArtifacts(artifacts)
	if err != nil {
		return result, err
	}
	if !artifacts.active {
		return result, nil
	}
	result.active = true
	result.hookExecutable = artifacts.parsed.HookExecutable
	result.gatewayAddr = artifacts.parsed.GatewayAddr
	result.gatewayServiceName = artifacts.parsed.GatewayServiceName
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return result, errors.New("enterprise hooks: current Cursor hook token has no user SID")
	}
	result.targetSID = user.User.Sid
	for _, target := range artifacts.parsed.Targets {
		if strings.EqualFold(target.SID, result.targetSID.String()) {
			result.registered = true
			result.dataDir = target.DataDir
			if artifacts.parsed.TargetFailModes != nil {
				result.hookFailMode = cursorManagedTargetFailMode(artifacts.parsed, target.SID)
			}
			break
		}
	}
	if !result.registered {
		return result, nil
	}
	home := filepath.Dir(result.dataDir)
	verifiedHome, verifiedSID, err := validateWindowsEnterpriseHome(home, result.targetSID.String())
	if err != nil {
		return result, err
	}
	if !sameWindowsEnterprisePath(home, verifiedHome) || !verifiedSID.Equals(result.targetSID) {
		return result, errors.New("enterprise hooks: Cursor managed profile identity changed")
	}
	return result, nil
}

func windowsCursorOptionsMatch(
	state windowsCursorManagedPolicyState,
	opts WindowsCursorManagedPolicyTeardownOptions,
) error {
	targets, err := canonicalWindowsCursorManagedTargets(opts.Targets, true)
	if err != nil {
		return err
	}
	gateway, err := connector.NormalizeWindowsManagedGatewayAddr(opts.GatewayAddr)
	if err != nil || gateway != state.GatewayAddr ||
		!sameWindowsEnterprisePath(opts.HookExecutable, state.HookExecutable) ||
		opts.GatewayServiceName != state.GatewayServiceName ||
		len(targets) != len(state.Targets) {
		return errors.New("enterprise hooks: Cursor machine enrollment does not match the protected lifecycle")
	}
	for i := range targets {
		if targets[i] != state.Targets[i] {
			return errors.New("enterprise hooks: Cursor target set does not match the protected lifecycle")
		}
	}
	return nil
}

// windowsCursorOptionsAllowState validates a partially completed lifecycle
// against the protected manifest without requiring every allowed target to
// have reached the global SID registry. A failed multi-user install can leave
// any non-empty prefix/subset enrolled before the installer restores its
// journaled preimage.
func windowsCursorOptionsAllowState(
	state windowsCursorManagedPolicyState,
	opts WindowsCursorManagedPolicyTeardownOptions,
) error {
	targets, err := canonicalWindowsCursorManagedTargets(opts.Targets, false)
	if err != nil {
		return err
	}
	gateway, err := connector.NormalizeWindowsManagedGatewayAddr(opts.GatewayAddr)
	if err != nil || gateway != state.GatewayAddr ||
		!sameWindowsEnterprisePath(opts.HookExecutable, state.HookExecutable) ||
		opts.GatewayServiceName != state.GatewayServiceName ||
		len(state.Targets) > len(targets) {
		return errors.New("enterprise hooks: Cursor machine enrollment is outside the protected lifecycle")
	}
	allowed := make(map[string]string, len(targets))
	for _, target := range targets {
		allowed[strings.ToUpper(target.SID)] = target.DataDir
	}
	for _, target := range state.Targets {
		dataDir, ok := allowed[strings.ToUpper(target.SID)]
		if !ok || !sameWindowsEnterprisePath(dataDir, target.DataDir) {
			return errors.New("enterprise hooks: Cursor target set is outside the protected lifecycle")
		}
	}
	return nil
}

// validateWindowsCursorLifecycleRestoreSource accepts a normal active or
// inactive policy and exact activation/upgrade write prefixes emitted by
// installWindowsCursorManagedPolicy: adapter, then private receipt, then
// public state, with hooks.json activated last. This path is used only while
// restoring an authenticated installer journal; ordinary install/repair
// validation remains strict and refuses incomplete ownership state.
func validateWindowsCursorLifecycleRestoreSource(
	current windowsCursorManagedArtifacts,
	allowedCurrent WindowsCursorManagedPolicyTeardownOptions,
	prior WindowsCursorManagedPolicyTeardownOptions,
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
) error {
	if err := validateWindowsCursorManagedTeardownSnapshot(prior, snapshot); err != nil {
		return err
	}
	if windowsCursorManagedArtifactsMatchSnapshot(current, snapshot) {
		return nil
	}
	validated, strictErr := validateWindowsCursorManagedArtifacts(current)
	if strictErr == nil {
		if !validated.active {
			return errors.New("enterprise hooks: current inactive Cursor policy does not match the journaled preimage")
		}
		return windowsCursorOptionsAllowState(validated.parsed, allowedCurrent)
	}
	if !snapshot.PolicyActive && len(prior.Targets) != 0 {
		return strictErr
	}
	if !current.adapter.existed || bytes.Equal(current.adapter.data, windowsCursorManagedTombstone()) ||
		current.state.existed && !current.receipt.existed {
		return strictErr
	}
	if !windowsCursorManagedFileSnapshotEqual(
		current.hooks,
		current.hooksMetadata,
		windowsManagedFileSnapshot{
			path:    current.hooks.path,
			existed: snapshot.HooksExisted,
			data:    snapshot.Hooks,
		},
		windowsCursorManagedFileMetadata{
			securityDescriptor: snapshot.HooksSecurityDescriptor,
			attributes:         snapshot.HooksAttributes,
		},
	) {
		return errors.New("enterprise hooks: Cursor enterprise config changed during partial activation")
	}
	for _, item := range []windowsManagedFileSnapshot{current.adapter, current.receipt, current.state} {
		if !item.existed {
			continue
		}
		if err := windowsManagedPolicyFileTrustCheck(item.path); err != nil {
			return fmt.Errorf("enterprise hooks: untrusted partial Cursor artifact %s: %w", item.path, err)
		}
	}
	// A partial, administrator-owned publication may precede the state file.
	// Accept only exact canonical bytes of a supported delivery mode;
	// identity, ownership, journal and hook-config preimage checks still
	// apply.
	expectedAdapter, err := connector.RenderWindowsCursorEnterpriseAdapter(
		allowedCurrent.HookExecutable,
		"closed",
	)
	if err == nil && !bytes.Equal(current.adapter.data, expectedAdapter) {
		expectedAdapter, err = connector.RenderWindowsCursorEnterpriseAdapter(allowedCurrent.HookExecutable, "open")
	}
	if err != nil || !bytes.Equal(current.adapter.data, expectedAdapter) {
		modes, mapErr := connector.WindowsCursorEnterpriseAdapterTargetModes(current.adapter.data, allowedCurrent.HookExecutable)
		if mapErr != nil {
			return errors.New("enterprise hooks: partial Cursor adapter identity changed")
		}
		authorizedTargets, targetErr := canonicalWindowsCursorManagedTargets(allowedCurrent.Targets, false)
		if targetErr != nil {
			return targetErr
		}
		allowed := make(map[string]bool, len(authorizedTargets))
		for _, target := range authorizedTargets {
			allowed[target.SID] = true
		}
		for sid, mode := range modes {
			if !allowed[sid] {
				return errors.New("enterprise hooks: partial Cursor adapter contains an unauthorized target")
			}
			if mode != "closed" && mode != "open" {
				return errors.New("enterprise hooks: partial Cursor adapter delivery mode is invalid")
			}
		}
	}
	expectedReceipt := windowsCursorManagedPolicyReceipt{
		SchemaVersion:                    1,
		ConfigPreexisting:                snapshot.HooksExisted,
		ConfigOriginal:                   append([]byte(nil), snapshot.Hooks...),
		ConfigOriginalSecurityDescriptor: snapshot.HooksSecurityDescriptor,
		ConfigOriginalAttributes:         snapshot.HooksAttributes,
	}
	if snapshot.HooksExisted {
		expectedReceipt.ConfigOriginalSHA256 = windowsManagedPolicyDigest(snapshot.Hooks)
	}
	receiptBody, err := windowsCursorManagedReceiptBody(expectedReceipt)
	if err != nil {
		return err
	}
	if snapshot.PolicyActive {
		// Upgrade preserves the private receipt exactly. The authenticated
		// preimage already validated its ACL, identity and digest above.
		receiptBody = snapshot.Receipt
		if !current.receipt.existed || !current.state.existed {
			return errors.New("enterprise hooks: Cursor upgrade removed protected ownership artifacts")
		}
	}
	if current.receipt.existed && !bytes.Equal(current.receipt.data, receiptBody) {
		return errors.New("enterprise hooks: partial Cursor rollback receipt does not match the journaled preimage")
	}
	if current.receipt.existed {
		if err := validateWindowsCursorPrivateReceiptMetadata(current.receiptMetadata); err != nil {
			return err
		}
	}
	if !current.state.existed {
		return nil
	}
	if snapshot.PolicyActive && windowsCursorManagedFileSnapshotEqual(current.state, current.stateMetadata,
		windowsManagedFileSnapshot{path: current.state.path, existed: true, data: snapshot.State},
		windowsCursorManagedFileMetadata{securityDescriptor: snapshot.StateSecurityDescriptor, attributes: snapshot.StateAttributes}) {
		// The new canonical adapter may be durable before the old state is
		// replaced. Only an exact journaled state preimage is accepted here.
		return nil
	}
	current, err = validateWindowsCursorManagedStateIdentity(current)
	if err != nil {
		return err
	}
	if current.parsed.ReceiptSHA256 != windowsManagedPolicyDigest(receiptBody) {
		return errors.New("enterprise hooks: partial Cursor state is not bound to the journaled receipt")
	}
	return windowsCursorOptionsAllowState(current.parsed, allowedCurrent)
}

func windowsCursorManagedArtifactsMatchSnapshot(
	artifacts windowsCursorManagedArtifacts,
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
) bool {
	for _, item := range []struct {
		current         windowsManagedFileSnapshot
		currentMetadata windowsCursorManagedFileMetadata
		existed         bool
		data            []byte
		descriptor      string
		attributes      uint32
	}{
		{artifacts.hooks, artifacts.hooksMetadata, snapshot.HooksExisted, snapshot.Hooks, snapshot.HooksSecurityDescriptor, snapshot.HooksAttributes},
		{artifacts.adapter, artifacts.adapterMetadata, snapshot.AdapterExisted, snapshot.Adapter, snapshot.AdapterSecurityDescriptor, snapshot.AdapterAttributes},
		{artifacts.state, artifacts.stateMetadata, snapshot.StateExisted, snapshot.State, snapshot.StateSecurityDescriptor, snapshot.StateAttributes},
		{artifacts.receipt, artifacts.receiptMetadata, snapshot.ReceiptExisted, snapshot.Receipt, snapshot.ReceiptSecurityDescriptor, snapshot.ReceiptAttributes},
	} {
		expected := windowsManagedFileSnapshot{
			path:    item.current.path,
			existed: item.existed,
			data:    item.data,
		}
		expectedMetadata := windowsCursorManagedFileMetadata{
			securityDescriptor: item.descriptor,
			attributes:         item.attributes,
		}
		if !windowsCursorManagedFileSnapshotEqual(
			item.current,
			item.currentMetadata,
			expected,
			expectedMetadata,
		) {
			return false
		}
	}
	return true
}

func windowsCursorManagedTeardownSnapshot(
	artifacts windowsCursorManagedArtifacts,
) WindowsCursorManagedPolicyTeardownSnapshot {
	return WindowsCursorManagedPolicyTeardownSnapshot{
		PolicyActive:              artifacts.active,
		HooksExisted:              artifacts.hooks.existed,
		Hooks:                     append([]byte(nil), artifacts.hooks.data...),
		HooksSecurityDescriptor:   artifacts.hooksMetadata.securityDescriptor,
		HooksAttributes:           artifacts.hooksMetadata.attributes,
		AdapterExisted:            artifacts.adapter.existed,
		Adapter:                   append([]byte(nil), artifacts.adapter.data...),
		AdapterSecurityDescriptor: artifacts.adapterMetadata.securityDescriptor,
		AdapterAttributes:         artifacts.adapterMetadata.attributes,
		StateExisted:              artifacts.state.existed,
		State:                     append([]byte(nil), artifacts.state.data...),
		StateSecurityDescriptor:   artifacts.stateMetadata.securityDescriptor,
		StateAttributes:           artifacts.stateMetadata.attributes,
		ReceiptExisted:            artifacts.receipt.existed,
		Receipt:                   append([]byte(nil), artifacts.receipt.data...),
		ReceiptSecurityDescriptor: artifacts.receiptMetadata.securityDescriptor,
		ReceiptAttributes:         artifacts.receiptMetadata.attributes,
	}
}

func validateWindowsCursorManagedTeardownSnapshot(
	opts WindowsCursorManagedPolicyTeardownOptions,
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
) error {
	for _, item := range []struct {
		name       string
		existed    bool
		data       []byte
		descriptor string
		attributes uint32
		limit      int
	}{
		{"hooks", snapshot.HooksExisted, snapshot.Hooks, snapshot.HooksSecurityDescriptor, snapshot.HooksAttributes, windowsCursorManagedHooksLimit},
		{"adapter", snapshot.AdapterExisted, snapshot.Adapter, snapshot.AdapterSecurityDescriptor, snapshot.AdapterAttributes, windowsCursorManagedAdapterLimit},
		{"state", snapshot.StateExisted, snapshot.State, snapshot.StateSecurityDescriptor, snapshot.StateAttributes, windowsCursorManagedStateLimit},
		{"receipt", snapshot.ReceiptExisted, snapshot.Receipt, snapshot.ReceiptSecurityDescriptor, snapshot.ReceiptAttributes, windowsCursorManagedReceiptLimit},
	} {
		if !item.existed {
			if len(item.data) != 0 || item.descriptor != "" || item.attributes != 0 {
				return fmt.Errorf("enterprise hooks: absent Cursor %s snapshot contains metadata", item.name)
			}
			continue
		}
		if len(item.data) > item.limit || item.descriptor == "" || item.attributes == 0 ||
			item.attributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
			return fmt.Errorf("enterprise hooks: Cursor %s snapshot is invalid", item.name)
		}
		descriptor, err := windows.SecurityDescriptorFromString(item.descriptor)
		if err != nil || descriptor == nil || !descriptor.IsValid() {
			return fmt.Errorf("enterprise hooks: Cursor %s snapshot security descriptor is invalid", item.name)
		}
	}
	if !snapshot.PolicyActive {
		if len(opts.Targets) != 0 || snapshot.StateExisted || snapshot.ReceiptExisted {
			return errors.New("enterprise hooks: inactive Cursor snapshot has active ownership state")
		}
		if snapshot.AdapterExisted && !bytes.Equal(snapshot.Adapter, windowsCursorManagedTombstone()) {
			return errors.New("enterprise hooks: inactive Cursor snapshot has an active adapter")
		}
		return nil
	}
	if !snapshot.HooksExisted || !snapshot.AdapterExisted || !snapshot.StateExisted ||
		!snapshot.ReceiptExisted {
		return errors.New("enterprise hooks: active Cursor snapshot is incomplete")
	}
	if err := validateWindowsCursorPrivateReceiptMetadata(windowsCursorManagedFileMetadata{
		securityDescriptor: snapshot.ReceiptSecurityDescriptor,
		attributes:         snapshot.ReceiptAttributes,
	}); err != nil {
		return err
	}
	var state windowsCursorManagedPolicyState
	decoder := json.NewDecoder(bytes.NewReader(snapshot.State))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("enterprise hooks: parse Cursor snapshot ownership state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("enterprise hooks: Cursor snapshot ownership state contains trailing JSON")
	}
	if (state.HookFailMode != "" && state.HookFailMode != "open" && state.HookFailMode != "closed") || state.SchemaVersion != 1 || !filepath.IsAbs(state.HookExecutable) ||
		filepath.Clean(state.HookExecutable) != state.HookExecutable ||
		state.ReceiptSHA256 != windowsManagedPolicyDigest(snapshot.Receipt) {
		return errors.New("enterprise hooks: Cursor snapshot has an invalid hook identity")
	}
	gateway, err := connector.NormalizeWindowsManagedGatewayAddr(state.GatewayAddr)
	if err != nil || gateway != state.GatewayAddr {
		return errors.New("enterprise hooks: Cursor snapshot has an invalid gateway identity")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(state.GatewayServiceName); err != nil {
		return err
	}
	targets, err := canonicalWindowsCursorManagedTargets(state.Targets, false)
	if err != nil || (len(targets) == 0 && (state.TargetFailModes != nil || cursorManagedPolicyFailMode(state) != "closed")) {
		return errors.New("enterprise hooks: Cursor snapshot has an invalid target set")
	}
	state.Targets = targets
	if _, err := renderWindowsCursorManagedAdapter(state); err != nil ||
		!windowsCursorManagedAdapterMatchesState(state, snapshot.Adapter) {
		return errors.New("enterprise hooks: Cursor snapshot adapter identity is invalid")
	}
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
	adapterPath := paths.Adapter
	if err := connector.VerifyWindowsCursorEnterpriseHooksForMigration(snapshot.Hooks, adapterPath, cursorManagedPolicyFailMode(state)); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor snapshot hook contract is invalid: %w", err)
	}
	var receipt windowsCursorManagedPolicyReceipt
	receiptDecoder := json.NewDecoder(bytes.NewReader(snapshot.Receipt))
	receiptDecoder.DisallowUnknownFields()
	if err := receiptDecoder.Decode(&receipt); err != nil {
		return fmt.Errorf("enterprise hooks: parse Cursor snapshot receipt: %w", err)
	}
	if err := receiptDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("enterprise hooks: Cursor snapshot receipt contains trailing JSON")
	}
	if receipt.SchemaVersion != 1 {
		return errors.New("enterprise hooks: Cursor snapshot receipt has an invalid schema")
	}
	if receipt.ConfigPreexisting {
		if receipt.ConfigOriginalSHA256 != windowsManagedPolicyDigest(receipt.ConfigOriginal) ||
			receipt.ConfigOriginalSecurityDescriptor == "" || receipt.ConfigOriginalAttributes == 0 {
			return errors.New("enterprise hooks: Cursor snapshot original-config receipt is invalid")
		}
	} else if len(receipt.ConfigOriginal) != 0 || receipt.ConfigOriginalSHA256 != "" ||
		receipt.ConfigOriginalSecurityDescriptor != "" || receipt.ConfigOriginalAttributes != 0 {
		return errors.New("enterprise hooks: Cursor snapshot has unexpected original-config metadata")
	}
	return windowsCursorOptionsMatch(state, opts)
}

func restoreWindowsCursorManagedSnapshotUnlocked(
	opts WindowsCursorManagedPolicyTeardownOptions,
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
	current windowsCursorManagedArtifacts,
	allowDeactivatedReceiptMetadata bool,
) error {
	if err := validateWindowsCursorManagedTeardownSnapshot(opts, snapshot); err != nil {
		return err
	}
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
	hooksPath := paths.Hooks
	adapterPath := paths.Adapter
	statePath := paths.State
	receiptPath := paths.Receipt
	if err := windowsCursorRestoreHooksCompatible(
		current,
		snapshot,
		adapterPath,
		allowDeactivatedReceiptMetadata,
	); err != nil {
		return err
	}
	type cursorRestoreItem struct {
		snapshot        windowsManagedFileSnapshot
		metadata        windowsCursorManagedFileMetadata
		current         windowsManagedFileSnapshot
		currentMetadata windowsCursorManagedFileMetadata
	}
	// adapter, receipt and state are DefenseClaw's own files, under the
	// DefenseClaw lock. hooks.json is shared and is restored last, below.
	items := []cursorRestoreItem{
		{snapshot: windowsManagedFileSnapshot{path: adapterPath, existed: snapshot.AdapterExisted, data: snapshot.Adapter}, metadata: windowsCursorManagedFileMetadata{securityDescriptor: snapshot.AdapterSecurityDescriptor, attributes: snapshot.AdapterAttributes}, current: current.adapter, currentMetadata: current.adapterMetadata},
		{snapshot: windowsManagedFileSnapshot{path: receiptPath, existed: snapshot.ReceiptExisted, data: snapshot.Receipt}, metadata: windowsCursorManagedFileMetadata{securityDescriptor: snapshot.ReceiptSecurityDescriptor, attributes: snapshot.ReceiptAttributes}, current: current.receipt, currentMetadata: current.receiptMetadata},
		{snapshot: windowsManagedFileSnapshot{path: statePath, existed: snapshot.StateExisted, data: snapshot.State}, metadata: windowsCursorManagedFileMetadata{securityDescriptor: snapshot.StateSecurityDescriptor, attributes: snapshot.StateAttributes}, current: current.state, currentMetadata: current.stateMetadata},
	}
	// On standalone only a file the snapshot does not already match is
	// written back, and only those are put back on a failed restore. A
	// teardown that never touched a file (an administrator's hooks.json under
	// an inactive policy, GAP-0028) must not have its bytes, owner or access
	// list rewritten by the rollback: re-applying its inherited descriptor and
	// requiring DefenseClaw's file trust failed the rollback, which left the
	// refused uninstall pending with every service stopped and disabled.
	// Secure Client keeps its earlier restore, which writes every file back
	// and puts every file back on failure (Secure Client is out of scope for
	// this fix).
	standalone := windowsEnterpriseStandaloneProcess()
	validatedHooks := windowsManagedFileSnapshot{path: hooksPath, existed: current.hooks.existed, data: current.hooks.data}
	renderHooks, err := windowsCursorRestoreHooksRender(snapshot, validatedHooks, current.hooksMetadata, adapterPath, standalone)
	if err != nil {
		return err
	}
	var written []cursorRestoreItem
	var hooksWrite windowsCursorManagedHooksWrite
	rollback := func(cause error) error {
		var failures []string
		// hooks.json is put back only over the restore's own bytes: a save an
		// administrator made since is newer and is kept.
		if restoreErr := hooksWrite.undo(); restoreErr != nil {
			failures = append(failures, restoreErr.Error())
		}
		if standalone {
			for index := len(written) - 1; index >= 0; index-- {
				item := written[index]
				if restoreErr := restoreWindowsCursorManagedFile(item.current, item.currentMetadata); restoreErr != nil {
					failures = append(failures, restoreErr.Error())
				}
			}
		} else {
			for _, item := range items {
				if restoreErr := restoreWindowsCursorManagedFile(item.current, item.currentMetadata); restoreErr != nil {
					failures = append(failures, restoreErr.Error())
				}
			}
		}
		if len(failures) != 0 {
			return fmt.Errorf("%v (Cursor snapshot rollback failed: %s)", cause, strings.Join(failures, "; "))
		}
		return cause
	}
	for _, item := range items {
		if standalone && windowsCursorManagedFileSnapshotEqual(item.current, item.currentMetadata, item.snapshot, item.metadata) {
			continue
		}
		written = append(written, item)
		if err := restoreWindowsCursorManagedFile(item.snapshot, item.metadata); err != nil {
			return rollback(err)
		}
	}
	// Administrators and Cursor save hooks.json without the DefenseClaw lock:
	// the journaled file is published only over the file this restore
	// validated, and a newer save is kept with DefenseClaw's journaled
	// registration merged in (publishWindowsCursorManagedHooks).
	if hooksWrite, err = publishWindowsCursorManagedHooks(validatedHooks, renderHooks); err != nil {
		return rollback(err)
	}
	wantHooks, wantHooksMetadata := windowsCursorRestoredHooks(hooksWrite, validatedHooks, current.hooksMetadata)
	restored, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		return rollback(err)
	}
	if snapshot.PolicyActive {
		restored, err = validateWindowsCursorManagedArtifacts(restored)
		if err != nil || !restored.active {
			if err == nil {
				err = errors.New("restored Cursor policy is inactive")
			}
			return rollback(err)
		}
		if err := windowsCursorOptionsMatch(restored.parsed, opts); err != nil {
			return rollback(err)
		}
	} else if restored.state.existed || restored.receipt.existed ||
		restored.hooks.existed != wantHooks.existed ||
		restored.adapter.existed != snapshot.AdapterExisted ||
		restored.receipt.existed != snapshot.ReceiptExisted ||
		!bytes.Equal(restored.hooks.data, wantHooks.data) ||
		!bytes.Equal(restored.adapter.data, snapshot.Adapter) ||
		!bytes.Equal(restored.receipt.data, snapshot.Receipt) ||
		(wantHooksMetadata != nil && restored.hooksMetadata != *wantHooksMetadata) ||
		restored.adapterMetadata.securityDescriptor != snapshot.AdapterSecurityDescriptor ||
		restored.adapterMetadata.attributes != snapshot.AdapterAttributes ||
		restored.receiptMetadata.securityDescriptor != snapshot.ReceiptSecurityDescriptor ||
		restored.receiptMetadata.attributes != snapshot.ReceiptAttributes {
		return rollback(errors.New("inactive Cursor snapshot was not restored exactly"))
	}
	return nil
}

// windowsCursorRestoreHooksRender returns the restore's edit of the shared
// hooks.json, as publishWindowsCursorManagedHooks renders it on the file it
// reads. Over the file the restore validated (validated) the edit is the
// journaled file with its journaled metadata; on standalone a file that
// already is the journaled one is left alone. A newer file is an
// administrator's or Cursor's save and is kept: an active snapshot merges its
// registration, at the journaled fail mode, into it, and an inactive one
// removes DefenseClaw's entries from it.
func windowsCursorRestoreHooksRender(
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
	validated windowsManagedFileSnapshot,
	validatedMetadata windowsCursorManagedFileMetadata,
	adapterPath string,
	standalone bool,
) (func(windowsManagedFileSnapshot) (windowsCursorManagedHooksEdit, error), error) {
	journaled := windowsManagedFileSnapshot{path: validated.path, existed: snapshot.HooksExisted, data: snapshot.Hooks}
	journaledMetadata := windowsCursorManagedFileMetadata{
		securityDescriptor: snapshot.HooksSecurityDescriptor,
		attributes:         snapshot.HooksAttributes,
	}
	failMode := ""
	if snapshot.PolicyActive {
		var state windowsCursorManagedPolicyState
		if err := json.Unmarshal(snapshot.State, &state); err != nil {
			return nil, fmt.Errorf("enterprise hooks: parse Cursor snapshot ownership state: %w", err)
		}
		failMode = cursorManagedPolicyFailMode(state)
	}
	return func(base windowsManagedFileSnapshot) (windowsCursorManagedHooksEdit, error) {
		if base.existed == validated.existed && bytes.Equal(base.data, validated.data) {
			if standalone && windowsCursorManagedFileSnapshotEqual(validated, validatedMetadata, journaled, journaledMetadata) {
				// Already the journaled file: an edit that changes nothing.
				if !base.existed {
					return windowsCursorManagedHooksEdit{remove: true}, nil
				}
				return windowsCursorManagedHooksEdit{data: base.data}, nil
			}
			if !journaled.existed {
				return windowsCursorManagedHooksEdit{remove: true}, nil
			}
			metadata := journaledMetadata
			return windowsCursorManagedHooksEdit{data: append([]byte(nil), journaled.data...), metadata: &metadata}, nil
		}
		if snapshot.PolicyActive {
			hooks, err := mergeWindowsCursorManagedRebuildHooks(base, adapterPath, failMode, false)
			if err != nil {
				return windowsCursorManagedHooksEdit{}, err
			}
			return windowsCursorManagedHooksEdit{data: hooks}, nil
		}
		if !base.existed {
			return windowsCursorManagedHooksEdit{remove: true}, nil
		}
		cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(base.data, adapterPath)
		if err != nil {
			return windowsCursorManagedHooksEdit{}, err
		}
		if !journaled.existed && connector.WindowsCursorEnterpriseHooksEmpty(cleaned) {
			return windowsCursorManagedHooksEdit{remove: true}, nil
		}
		return windowsCursorManagedHooksEdit{data: cleaned}, nil
	}, nil
}

// windowsCursorRestoredHooks is the hooks.json a restore left: what it
// published, or the file it last read when the edit changed nothing. The
// metadata is nil when the restore cannot know it: a new file gets
// DefenseClaw's protection, and a newer save left alone keeps its own.
func windowsCursorRestoredHooks(
	write windowsCursorManagedHooksWrite,
	validated windowsManagedFileSnapshot,
	validatedMetadata windowsCursorManagedFileMetadata,
) (windowsManagedFileSnapshot, *windowsCursorManagedFileMetadata) {
	if !write.written {
		if write.replaced.existed == validated.existed && bytes.Equal(write.replaced.data, validated.data) {
			metadata := validatedMetadata
			return validated, &metadata
		}
		return write.replaced, nil
	}
	hooks := windowsManagedFileSnapshot{path: validated.path, existed: !write.edit.remove, data: write.edit.data}
	switch {
	case write.edit.remove:
		return hooks, nil
	case write.edit.metadata != nil:
		metadata := *write.edit.metadata
		return hooks, &metadata
	case write.replaced.existed:
		metadata := write.replacedMetadata
		return hooks, &metadata
	default:
		return hooks, nil
	}
}

func windowsCursorRestoreHooksCompatible(
	current windowsCursorManagedArtifacts,
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
	adapterPath string,
	allowDeactivatedReceiptMetadata bool,
) error {
	currentRemainder, err := connector.RemoveWindowsCursorEnterpriseHooks(
		current.hooks.data,
		adapterPath,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect current Cursor config before restore: %w", err)
	}
	snapshotRemainder, err := connector.RemoveWindowsCursorEnterpriseHooks(
		snapshot.Hooks,
		adapterPath,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect journaled Cursor config before restore: %w", err)
	}
	if !connector.WindowsCursorEnterpriseHooksOwnedRemainderEqual(
		currentRemainder,
		snapshotRemainder,
	) {
		return errors.New("enterprise hooks: refusing Cursor restore after a concurrent enterprise-config change")
	}
	if current.hooks.existed && snapshot.HooksExisted &&
		(current.hooksMetadata.securityDescriptor != snapshot.HooksSecurityDescriptor ||
			current.hooksMetadata.attributes != snapshot.HooksAttributes) {
		if !allowDeactivatedReceiptMetadata ||
			!windowsCursorMatchesReceiptOriginal(current, snapshot) {
			return errors.New("enterprise hooks: refusing Cursor restore after a concurrent enterprise-config ACL change")
		}
	}
	return nil
}

func windowsCursorMatchesReceiptOriginal(
	current windowsCursorManagedArtifacts,
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
) bool {
	if !snapshot.PolicyActive || !snapshot.ReceiptExisted {
		return false
	}
	var receipt windowsCursorManagedPolicyReceipt
	decoder := json.NewDecoder(bytes.NewReader(snapshot.Receipt))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false
	}
	return receipt.SchemaVersion == 1 && receipt.ConfigPreexisting &&
		receipt.ConfigOriginalSHA256 == windowsManagedPolicyDigest(receipt.ConfigOriginal) &&
		bytes.Equal(current.hooks.data, receipt.ConfigOriginal) &&
		current.hooksMetadata.securityDescriptor == receipt.ConfigOriginalSecurityDescriptor &&
		current.hooksMetadata.attributes == receipt.ConfigOriginalAttributes
}

func CaptureWindowsCursorManagedPolicySnapshot(
	opts WindowsCursorManagedPolicyTeardownOptions,
) (WindowsCursorManagedPolicyTeardownSnapshot, error) {
	var snapshot WindowsCursorManagedPolicyTeardownSnapshot
	err := withWindowsCursorManagedTransaction(func() error {
		currentArtifacts, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		artifacts, err := validateWindowsCursorManagedArtifactsReclaimingOrphans(currentArtifacts)
		if err != nil {
			return err
		}
		if !artifacts.active {
			if len(opts.Targets) != 0 {
				return errors.New("enterprise hooks: expected Cursor managed policy is absent")
			}
			snapshot = windowsCursorManagedTeardownSnapshot(artifacts)
			return nil
		}
		if err := windowsCursorOptionsMatch(artifacts.parsed, opts); err != nil {
			// Strict mode (DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS=1)
			// preserves the refuse-on-drift posture - a hardened
			// deployment must NOT silently reclaim identity-drifted
			// artifacts because that masks the exact tamper signal
			// operators configure strict mode to catch.
			if managed.TrustStrictAncestors() {
				return err
			}
			// Bulldoze: the Cursor managed artifacts authenticated as OURS
			// (validateWindowsCursorManagedArtifacts passed above) but their
			// scoped identity does not match the current install (same
			// pattern as the IPC orphan-SID and Claude managed-policy
			// reclaims: prior unsigned certification install with a
			// different scoped GatewayServiceName left state at the fixed
			// Cursor managed root, which is independent of --install-root/
			// --state-root). Call the authenticated deactivate helper on
			// the on-disk state so hooks.json has only the stale DefenseClaw
			// entries surgically removed (per the receipt's
			// ConfigPreexisting / ConfigOriginal), the state/receipt/adapter
			// are retired, and the capture returns an empty snapshot.
			// Install then writes a fresh canonical pair; rollback has no
			// stale snapshot to restore.
			//
			// The strict identity check remains for PrepareWindowsCursor...
			// Teardown / RestoreWindowsCursor... callers where recovery
			// MUST authenticate the exact prior deployment.
			fmt.Fprintf(os.Stderr,
				"[enterprise-hooks] reclaiming identity-drifted Cursor managed "+
					"artifacts at %s (prior scoped install's identity does not "+
					"match current scope): %v\n",
				artifacts.root, err)
			if deactivateErr := deactivateWindowsCursorManagedPolicyUnlocked(artifacts); deactivateErr != nil {
				return fmt.Errorf(
					"enterprise hooks: reclaim identity-drifted Cursor managed policy: %w",
					deactivateErr,
				)
			}
			// Resnapshot after deactivate so the empty snapshot matches
			// reality on disk (nothing left to restore on rollback).
			postArtifacts, postErr := snapshotWindowsCursorManagedArtifacts()
			if postErr != nil {
				return postErr
			}
			postValidated, postValidateErr := validateWindowsCursorManagedArtifacts(postArtifacts)
			if postValidateErr != nil {
				return postValidateErr
			}
			snapshot = windowsCursorManagedTeardownSnapshot(postValidated)
			return nil
		}
		snapshot = windowsCursorManagedTeardownSnapshot(artifacts)
		return nil
	})
	return snapshot, err
}

func PrepareWindowsCursorManagedPolicyTeardown(
	opts WindowsCursorManagedPolicyTeardownOptions,
	persist func(WindowsCursorManagedPolicyTeardownSnapshot) error,
) (WindowsCursorManagedPolicyTeardownSnapshot, error) {
	var captured WindowsCursorManagedPolicyTeardownSnapshot
	err := withWindowsCursorManagedTransaction(func() error {
		artifacts, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		artifacts, err = validateWindowsCursorManagedArtifacts(artifacts)
		if err != nil {
			return err
		}
		if artifacts.active {
			if err := windowsCursorOptionsMatch(artifacts.parsed, opts); err != nil {
				return err
			}
			captured = windowsCursorManagedTeardownSnapshot(artifacts)
		} else if len(opts.Targets) != 0 {
			return errors.New("enterprise hooks: expected Cursor managed policy is absent")
		} else {
			captured = windowsCursorManagedTeardownSnapshot(artifacts)
		}
		if persist == nil {
			return errors.New("enterprise hooks: Cursor teardown snapshot persistence callback is required")
		}
		if err := persist(captured); err != nil {
			return err
		}
		if artifacts.active {
			return deactivateWindowsCursorManagedPolicyUnlocked(artifacts)
		}
		return nil
	})
	return captured, err
}

func RestoreWindowsCursorManagedPolicyTeardown(
	opts WindowsCursorManagedPolicyTeardownOptions,
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
) error {
	return withWindowsCursorManagedTransaction(func() error {
		current, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		if current.state.existed {
			validated, validateErr := validateWindowsCursorManagedArtifacts(current)
			if validateErr == nil && validated.active {
				return errors.New("enterprise hooks: refusing Cursor teardown restore over an active policy")
			}
		}
		return restoreWindowsCursorManagedSnapshotUnlocked(opts, snapshot, current, true)
	})
}

func RestoreWindowsCursorManagedPolicySnapshot(
	prior WindowsCursorManagedPolicyTeardownOptions,
	current WindowsCursorManagedPolicyTeardownOptions,
	snapshot WindowsCursorManagedPolicyTeardownSnapshot,
) error {
	return withWindowsCursorManagedTransaction(func() error {
		currentArtifacts, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		if err := validateWindowsCursorLifecycleRestoreSource(
			currentArtifacts,
			current,
			prior,
			snapshot,
		); err != nil {
			return err
		}
		return restoreWindowsCursorManagedSnapshotUnlocked(prior, snapshot, currentArtifacts, false)
	})
}

func VerifyWindowsCursorManagedPolicyTeardown() error {
	artifacts, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		return err
	}
	if artifacts.state.existed {
		return errors.New("enterprise hooks: Cursor managed ownership state remains after teardown")
	}
	if artifacts.receipt.existed {
		return errors.New("enterprise hooks: Cursor managed rollback receipt remains after teardown")
	}
	if artifacts.adapter.existed && !bytes.Equal(artifacts.adapter.data, windowsCursorManagedTombstone()) {
		return errors.New("enterprise hooks: active Cursor adapter remains after teardown")
	}
	if artifacts.hooks.existed {
		cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(artifacts.hooks.data, artifacts.adapter.path)
		if err != nil {
			return err
		}
		if !connector.WindowsCursorEnterpriseHooksSemanticallyEqual(cleaned, artifacts.hooks.data) {
			return errors.New("enterprise hooks: Cursor enterprise hook references remain after teardown")
		}
	}
	return nil
}
