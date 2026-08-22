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

// WindowsCursorManagedRuntimeTarget binds a machine-authorized SID to only
// that user's canonical DefenseClaw runtime. No token is stored in ProgramData.
type WindowsCursorManagedRuntimeTarget struct {
	SID     string `json:"sid"`
	DataDir string `json:"data_dir"`
}

type windowsCursorManagedPolicyState struct {
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
}

func defaultWindowsCursorManagedRoot() (string, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve trusted ProgramData for Cursor: %w", err)
	}
	return filepath.Join(programData, "Cursor"), nil
}

func windowsCursorManagedPaths() (root, hooks, adapter, state, receipt, lock string, err error) {
	root, err = windowsCursorManagedRootResolver()
	if err != nil {
		return "", "", "", "", "", "", err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!strings.EqualFold(filepath.Base(root), "Cursor") {
		return "", "", "", "", "", "", fmt.Errorf(
			"enterprise hooks: refusing noncanonical Cursor enterprise root: %s",
			root,
		)
	}
	hooks = filepath.Join(root, windowsCursorManagedHooksFile)
	adapter = filepath.Join(root, windowsCursorManagedAdapterFile)
	state = filepath.Join(root, windowsCursorManagedStateFile)
	receipt = filepath.Join(root, windowsCursorManagedReceiptFile)
	lock = filepath.Join(root, windowsCursorManagedLockFile)
	return root, hooks, adapter, state, receipt, lock, nil
}

func withWindowsCursorManagedTransaction(fn func() error) error {
	root, _, _, _, _, lockPath, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
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
	_, _, _, _, receiptPath, _, err := windowsCursorManagedPaths()
	if err != nil {
		return result, err
	}
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
	root, hooksPath, adapterPath, statePath, _, _, err := windowsCursorManagedPaths()
	if err != nil {
		return windowsCursorManagedArtifacts{}, err
	}
	result := windowsCursorManagedArtifacts{root: root}
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

func writeWindowsCursorManagedFilePreservingMetadata(
	snapshot windowsManagedFileSnapshot,
	metadata windowsCursorManagedFileMetadata,
	data []byte,
) error {
	if err := windowsManagedPolicyWriter(snapshot.path, data, true); err != nil {
		return err
	}
	if snapshot.existed {
		return restoreWindowsCursorManagedFileMetadata(snapshot.path, metadata)
	}
	return nil
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
				return artifacts, errors.New("enterprise hooks: Cursor hook references remain without ownership metadata")
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
	if err := connector.VerifyWindowsCursorEnterpriseHooks(artifacts.hooks.data, artifacts.adapter.path, "closed"); err != nil {
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
	if state.SchemaVersion != 1 || !filepath.IsAbs(state.HookExecutable) ||
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
	if err != nil || len(targets) == 0 {
		return artifacts, errors.New("enterprise hooks: invalid Cursor managed target set")
	}
	state.Targets = targets
	expectedAdapter, err := connector.RenderWindowsCursorEnterpriseAdapter(state.HookExecutable, "closed")
	if err != nil {
		return artifacts, err
	}
	if state.AdapterSHA256 != windowsManagedPolicyDigest(expectedAdapter) ||
		!bytes.Equal(expectedAdapter, artifacts.adapter.data) {
		return artifacts, errors.New("enterprise hooks: Cursor enterprise adapter identity changed")
	}
	artifacts.parsed = state
	return artifacts, nil
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
	if targetSID == nil {
		return nil, errors.New("enterprise hooks: Cursor target SID is required")
	}
	targets, err := canonicalWindowsCursorManagedTargets([]WindowsCursorManagedRuntimeTarget{{
		SID: targetSID.String(), DataDir: dataDir,
	}}, true)
	if err != nil {
		return nil, err
	}
	var rollback func() error
	err = withWindowsCursorManagedTransaction(func() error {
		before, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		current, err := validateWindowsCursorManagedArtifacts(before)
		if err != nil {
			return err
		}
		gateway, err := connector.NormalizeWindowsManagedGatewayAddr(opts.APIAddr)
		if err != nil {
			return err
		}
		service := os.Getenv(connector.WindowsGatewayServiceNameEnv)
		if err := connector.ValidateWindowsManagedGatewayServiceName(service); err != nil {
			return err
		}
		adapterBody, err := connector.RenderWindowsCursorEnterpriseAdapter(opts.HookExecutable, "closed")
		if err != nil {
			return err
		}
		baseHooks := before.hooks.data
		if !before.hooks.existed {
			baseHooks = []byte("{}\n")
		} else if !current.active {
			if err := windowsManagedPolicyFileTrustCheck(before.hooks.path); err != nil {
				return fmt.Errorf("enterprise hooks: pre-existing Cursor enterprise config is not trusted: %w", err)
			}
		}
		hooksBody, err := connector.MergeWindowsCursorEnterpriseHooks(baseHooks, before.adapter.path, "closed")
		if err != nil {
			return err
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
		state.SchemaVersion = 1
		state.HookExecutable = filepath.Clean(opts.HookExecutable)
		state.GatewayAddr = gateway
		state.GatewayServiceName = service
		state.AdapterSHA256 = windowsManagedPolicyDigest(adapterBody)
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
		receiptBody, err := windowsCursorManagedReceiptBody(receipt)
		if err != nil {
			return err
		}
		state.ReceiptSHA256 = windowsManagedPolicyDigest(receiptBody)
		stateBody, err := windowsCursorManagedStateBody(state)
		if err != nil {
			return err
		}
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
			nowHooks, err := snapshotWindowsManagedFileWithLimit(before.hooks.path, windowsCursorManagedHooksLimit)
			if err != nil {
				failures = append(failures, err.Error())
			} else {
				nowMetadata, metadataErr := snapshotWindowsCursorManagedFileMetadata(nowHooks)
				if metadataErr != nil {
					failures = append(failures, metadataErr.Error())
				} else {
					installedHooks := windowsManagedFileSnapshot{path: before.hooks.path, existed: true, data: hooksBody}
					installedImageMatches := bytes.Equal(nowHooks.data, installedHooks.data) &&
						(!before.hooks.existed || nowMetadata == before.hooksMetadata)
					if windowsCursorManagedFileSnapshotEqual(nowHooks, nowMetadata, before.hooks, before.hooksMetadata) ||
						installedImageMatches {
						if err := restoreWindowsCursorManagedFile(before.hooks, before.hooksMetadata); err != nil {
							failures = append(failures, err.Error())
						}
					} else if current.active {
						// Preserve an administrator's unrelated concurrent update only
						// when the prior active policy remains fully callable.
						if err := connector.VerifyWindowsCursorEnterpriseHooks(
							nowHooks.data,
							before.adapter.path,
							"closed",
						); err != nil {
							failures = append(failures, fmt.Sprintf("concurrent Cursor config invalidated the restored policy: %v", err))
						}
					} else {
						// A fresh-install rollback must not leave a foreign-updated
						// hooks.json pointing at an adapter/state we just removed.
						cleaned, removeErr := connector.RemoveWindowsCursorEnterpriseHooks(
							nowHooks.data,
							before.adapter.path,
						)
						if removeErr != nil {
							failures = append(failures, fmt.Sprintf("remove DefenseClaw entries from concurrent Cursor config: %v", removeErr))
						} else if !bytes.Equal(cleaned, nowHooks.data) {
							if writeErr := writeWindowsCursorManagedFilePreservingMetadata(nowHooks, nowMetadata, cleaned); writeErr != nil {
								failures = append(failures, writeErr.Error())
							}
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
				}
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
		currentHooks, err := snapshotWindowsManagedFileWithLimit(before.hooks.path, windowsCursorManagedHooksLimit)
		if err != nil {
			return failMutation(err)
		}
		currentHooksMetadata, err := snapshotWindowsCursorManagedFileMetadata(currentHooks)
		if err != nil {
			return failMutation(err)
		}
		if !windowsCursorManagedFileSnapshotEqual(
			currentHooks,
			currentHooksMetadata,
			before.hooks,
			before.hooksMetadata,
		) {
			return failMutation(errors.New("enterprise hooks: Cursor enterprise config changed concurrently before activation"))
		}
		// Activation is last: Cursor cannot invoke the command before its adapter
		// and SID registry are durable and protected.
		if err := writeWindowsCursorManagedFilePreservingMetadata(
			before.hooks,
			before.hooksMetadata,
			hooksBody,
		); err != nil {
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
	})
	return rollback, err
}

func windowsCursorManagedTombstone() []byte {
	return []byte("# defenseclaw-managed-cursor-tombstone v1\r\n[Console]::Out.Write('{\"continue\":true}')\r\nexit 0\r\n")
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
		artifacts, err := validateWindowsCursorManagedArtifacts(current)
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
// reconciled. An empty set deactivates the global hook and leaves an inert
// adapter tombstone for already-running Cursor processes.
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
		artifacts, err := validateWindowsCursorManagedArtifacts(currentArtifacts)
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

func publishWindowsCursorManagedPolicyTargetsUnlocked(
	artifacts windowsCursorManagedArtifacts,
	targets []WindowsCursorManagedRuntimeTarget,
) error {
	if len(targets) > 0 {
		artifacts.parsed.Targets = targets
		body, err := windowsCursorManagedStateBody(artifacts.parsed)
		if err != nil {
			return err
		}
		return windowsManagedPolicyWriter(artifacts.state.path, body, true)
	}
	return deactivateWindowsCursorManagedPolicyUnlocked(artifacts)
}

func deactivateWindowsCursorManagedPolicyUnlocked(artifacts windowsCursorManagedArtifacts) error {
	currentHooks, err := snapshotWindowsManagedFileWithLimit(artifacts.hooks.path, windowsCursorManagedHooksLimit)
	if err != nil {
		return err
	}
	currentHooksMetadata, err := snapshotWindowsCursorManagedFileMetadata(currentHooks)
	if err != nil {
		return err
	}
	if !windowsCursorManagedFileSnapshotEqual(
		currentHooks,
		currentHooksMetadata,
		artifacts.hooks,
		artifacts.hooksMetadata,
	) {
		return errors.New("enterprise hooks: Cursor enterprise config changed concurrently before teardown")
	}
	rollback := func(cause error) error {
		var failures []string
		for _, item := range []struct {
			snapshot windowsManagedFileSnapshot
			metadata windowsCursorManagedFileMetadata
		}{
			{artifacts.adapter, artifacts.adapterMetadata},
			{artifacts.receipt, artifacts.receiptMetadata},
			{artifacts.state, artifacts.stateMetadata},
			{artifacts.hooks, artifacts.hooksMetadata},
		} {
			if err := restoreWindowsCursorManagedFile(item.snapshot, item.metadata); err != nil {
				failures = append(failures, err.Error())
			}
		}
		if len(failures) != 0 {
			return fmt.Errorf("%v (Cursor teardown rollback failed: %s)", cause, strings.Join(failures, "; "))
		}
		return cause
	}
	cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(
		artifacts.hooks.data,
		artifacts.adapter.path,
	)
	if err != nil {
		return err
	}
	hooksMetadata := artifacts.hooksMetadata
	if artifacts.parsedReceipt.ConfigPreexisting &&
		connector.WindowsCursorEnterpriseHooksOwnedRemainderEqual(cleaned, artifacts.parsedReceipt.ConfigOriginal) {
		cleaned = append([]byte(nil), artifacts.parsedReceipt.ConfigOriginal...)
		hooksMetadata = windowsCursorManagedFileMetadata{
			securityDescriptor: artifacts.parsedReceipt.ConfigOriginalSecurityDescriptor,
			attributes:         artifacts.parsedReceipt.ConfigOriginalAttributes,
		}
	}
	if !artifacts.parsedReceipt.ConfigPreexisting && connector.WindowsCursorEnterpriseHooksEmpty(cleaned) {
		if err := os.Remove(artifacts.hooks.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return rollback(err)
		}
	} else if err := writeWindowsCursorManagedFilePreservingMetadata(
		artifacts.hooks,
		hooksMetadata,
		cleaned,
	); err != nil {
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
		len(state.Targets) == 0 || len(state.Targets) > len(targets) {
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
// inactive policy and the exact fresh-activation write prefixes emitted by
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
	if snapshot.PolicyActive || len(prior.Targets) != 0 || len(allowedCurrent.Targets) == 0 {
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
	expectedAdapter, err := connector.RenderWindowsCursorEnterpriseAdapter(
		allowedCurrent.HookExecutable,
		"closed",
	)
	if err != nil || !bytes.Equal(current.adapter.data, expectedAdapter) {
		if err != nil {
			return err
		}
		return errors.New("enterprise hooks: partial Cursor adapter identity changed")
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
		!snapshot.ReceiptExisted || len(opts.Targets) == 0 {
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
	if state.SchemaVersion != 1 || !filepath.IsAbs(state.HookExecutable) ||
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
	if err != nil || len(targets) == 0 {
		return errors.New("enterprise hooks: Cursor snapshot has an invalid target set")
	}
	state.Targets = targets
	expectedAdapter, err := connector.RenderWindowsCursorEnterpriseAdapter(state.HookExecutable, "closed")
	if err != nil || state.AdapterSHA256 != windowsManagedPolicyDigest(expectedAdapter) ||
		!bytes.Equal(expectedAdapter, snapshot.Adapter) {
		return errors.New("enterprise hooks: Cursor snapshot adapter identity is invalid")
	}
	_, _, adapterPath, _, _, _, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(snapshot.Hooks, adapterPath, "closed"); err != nil {
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
	_, hooksPath, adapterPath, statePath, receiptPath, _, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
	if err := windowsCursorRestoreHooksCompatible(
		current,
		snapshot,
		adapterPath,
		allowDeactivatedReceiptMetadata,
	); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var failures []string
		for _, item := range []struct {
			snapshot windowsManagedFileSnapshot
			metadata windowsCursorManagedFileMetadata
		}{
			{current.adapter, current.adapterMetadata},
			{current.receipt, current.receiptMetadata},
			{current.state, current.stateMetadata},
			{current.hooks, current.hooksMetadata},
		} {
			if restoreErr := restoreWindowsCursorManagedFile(item.snapshot, item.metadata); restoreErr != nil {
				failures = append(failures, restoreErr.Error())
			}
		}
		if len(failures) != 0 {
			return fmt.Errorf("%v (Cursor snapshot rollback failed: %s)", cause, strings.Join(failures, "; "))
		}
		return cause
	}
	items := []struct {
		snapshot windowsManagedFileSnapshot
		metadata windowsCursorManagedFileMetadata
	}{
		{snapshot: windowsManagedFileSnapshot{path: adapterPath, existed: snapshot.AdapterExisted, data: snapshot.Adapter}, metadata: windowsCursorManagedFileMetadata{securityDescriptor: snapshot.AdapterSecurityDescriptor, attributes: snapshot.AdapterAttributes}},
		{snapshot: windowsManagedFileSnapshot{path: receiptPath, existed: snapshot.ReceiptExisted, data: snapshot.Receipt}, metadata: windowsCursorManagedFileMetadata{securityDescriptor: snapshot.ReceiptSecurityDescriptor, attributes: snapshot.ReceiptAttributes}},
		{snapshot: windowsManagedFileSnapshot{path: statePath, existed: snapshot.StateExisted, data: snapshot.State}, metadata: windowsCursorManagedFileMetadata{securityDescriptor: snapshot.StateSecurityDescriptor, attributes: snapshot.StateAttributes}},
		{snapshot: windowsManagedFileSnapshot{path: hooksPath, existed: snapshot.HooksExisted, data: snapshot.Hooks}, metadata: windowsCursorManagedFileMetadata{securityDescriptor: snapshot.HooksSecurityDescriptor, attributes: snapshot.HooksAttributes}},
	}
	for _, item := range items {
		if err := restoreWindowsCursorManagedFile(item.snapshot, item.metadata); err != nil {
			return rollback(err)
		}
	}
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
		restored.hooks.existed != snapshot.HooksExisted ||
		restored.adapter.existed != snapshot.AdapterExisted ||
		restored.receipt.existed != snapshot.ReceiptExisted ||
		!bytes.Equal(restored.hooks.data, snapshot.Hooks) ||
		!bytes.Equal(restored.adapter.data, snapshot.Adapter) ||
		!bytes.Equal(restored.receipt.data, snapshot.Receipt) ||
		restored.hooksMetadata.securityDescriptor != snapshot.HooksSecurityDescriptor ||
		restored.hooksMetadata.attributes != snapshot.HooksAttributes ||
		restored.adapterMetadata.securityDescriptor != snapshot.AdapterSecurityDescriptor ||
		restored.adapterMetadata.attributes != snapshot.AdapterAttributes ||
		restored.receiptMetadata.securityDescriptor != snapshot.ReceiptSecurityDescriptor ||
		restored.receiptMetadata.attributes != snapshot.ReceiptAttributes {
		return rollback(errors.New("inactive Cursor snapshot was not restored exactly"))
	}
	return nil
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
		artifacts, err := validateWindowsCursorManagedArtifacts(currentArtifacts)
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
			return err
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
