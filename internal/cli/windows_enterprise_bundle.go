//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Signed policy bundles on Windows (management plane spec P1 section 7).
// Setup /ensure BUNDLE=<file> (enterprise windows ensure --bundle) receives
// the bundle into the store under <state root>\etc\bundles, verifies the
// staged copy against the trust anchors in <state root>\etc\trust, promotes
// it to its read-only version directory and renders its config.yaml there.
// The ordinary ensure then installs that config, so its transaction (and
// its rollback) is the one CONFIG= uses. The bundle becomes current only
// when the running gateway reports the effective policy of the installed
// config; otherwise the last good config is installed again and the receipt
// fails. Bundle directories and private receipt state have explicit protected
// ACLs; receipts live in the administrator-only install folder. Standalone
// only: the Secure Client profile never reaches this file.

const (
	windowsBundleConfigName   = "bundle-config.yaml"
	windowsBundleRollbackName = "bundle-rollback-config.yaml"
	windowsBundleLockName     = "bundle.lock"
	// windowsBundleStagedAnchorsName is the private verification stage.
	// Before the config is installed, it moves to a receipt-specific path.
	windowsBundleStagedAnchorsName = "bundle-staged-anchors.json"
	windowsBundleMaxConfig         = 4 << 20
	windowsBundleMaxAnchors        = 256 << 10
	// Warnings of a changing run without --bundle that settles the
	// receipts a killed bundle run left (GAP-1302). The first three are the
	// codes Linux and macOS use for the same outcomes.
	windowsBundleInterruptedWarning = "bundle_interrupted"
	windowsBundleUnconfirmedWarning = "bundle_unconfirmed"
	// windowsBundlePendingMessage is the bundle_pending warning of a settle
	// that found a committed bundle while the gateway could not be read.
	windowsBundlePendingMessage         = "%d policy bundle(s) a previous run installed are not confirmed yet because the gateway could not be read (not running or not ready); they stay pending and are never failed for that: run `defenseclaw enterprise windows ensure --profile standalone` again once the gateway runs to confirm them"
	windowsBundleStateUnreadableWarning = "bundle_state_unreadable"
	windowsBundleSettleDeferredWarning  = "bundle_settle_deferred"
	windowsBundleMarkerFailedWarning    = "bundle_marker_failed"
	// windowsBundlePolicyWaits bounds how often the confirm re-reads the
	// gateway policy after a successful transaction (a hot reload lags).
	windowsBundlePolicyWaits = 4
)

var errWindowsBundleStoreBusy = errors.New("another policy bundle run holds the bundle store; retry when it ends")

// Seams for tests.
var (
	windowsBundleLayout                 = managed.StandaloneWindowsLayout
	windowsBundlePolicy                 = readWindowsBundleGatewayPolicy
	windowsBundleSleep                  = time.Sleep
	windowsBundleTrust                  = func(path string) error { return managed.ValidateTrustedFilePath(path, "policy bundle store") }
	windowsBundlePrivateStage           = privateWindowsBundleStage
	windowsBundleEnsureStageDirectory   = ensureWindowsBundleStageDirectory
	windowsBundlePublishStageFile       = publishWindowsBundlePrivateFile
	windowsBundleSealVersion            = sealWindowsBundleVersionAssets
	windowsBundlePublishVersion         = publishWindowsBundleVersion
	windowsBundlePublishReceipt         = publishWindowsBundleReceipt
	windowsBundleEnsureDirectory        = ensureWindowsBundleDirectory
	windowsBundleEnsurePrivateDirectory = ensureWindowsBundlePrivateDirectory
	windowsBundlePublishPrivateFile     = publishWindowsBundlePrivateFile
	windowsBundleSyncMarker             = syncWindowsBundleMarker
	// windowsBundleReadAnchors reads and checks an anchor file once.
	windowsBundleReadAnchors = enterprisebundle.ReadAnchorsFile
)

func init() {
	// bundle status and verify ask whether this is a standalone managed
	// device; on Windows the deployment record answers.
	bundleManagedDevice = windowsEnterpriseStandaloneInstalled
	// A standard user cannot read deployment.json, so bundle verify cannot
	// tell a managed device from an unmanaged one (GAP-0009).
	bundleDeviceRecordUnreadable = func() bool {
		if windowsEnterpriseIsElevated() {
			return false
		}
		deployment, err := windowsEnterpriseDeploymentInspector(managed.ProfileStandalone)
		return err == nil && deployment.State == winpath.EnterpriseDeploymentUnknown
	}
	bundlePrivilege = func() error {
		if !windowsEnterpriseIsElevated() {
			return &enterprisebundle.Error{Code: enterprisebundle.CodeNotAdmin,
				Detail: "run this command from an elevated administrator or SYSTEM session to read the managed bundle state"}
		}
		return nil
	}
	managedStandaloneBundleGeneration = windowsStagedBundleGeneration
	managedStandaloneBundleCurrent = windowsBundleCurrent
	bundleSettleStatus = settleWindowsBundleStatus
}

// settleWindowsBundleStatus closes the crash window between the applied
// receipt and the confirmed state. The store lock excludes a live apply; an
// active writer retains ownership and status reports its pending receipt.
func settleWindowsBundleStatus(ctx context.Context) error {
	_, err := settleWindowsBundleStatusReport(ctx)
	return err
}

// settleWindowsBundleStatusReport is settleWindowsBundleStatus that also
// returns the receipts still unsettled afterwards, read under the store
// lock: no live apply owns them, a killed one left them (GAP-0028). nil
// while a live apply holds the lock.
func settleWindowsBundleStatusReport(ctx context.Context) ([]*enterprisebundle.Receipt, error) {
	layout, err := windowsBundleLayout()
	if err != nil {
		return nil, err
	}
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		// A live apply may hold this lock. It will settle its own receipt.
		if errors.Is(err, errWindowsBundleStoreBusy) {
			return nil, nil
		}
		return nil, err
	}
	defer unlock()
	driver := newWindowsBundleDriver(layout)
	if err := settleWindowsBundleStatusLocked(ctx, layout, driver); err != nil {
		return nil, err
	}
	unsettled, _ := driver.Store.Unsettled()
	return unsettled, nil
}

func settleWindowsBundleStatusLocked(ctx context.Context, layout managed.StandaloneLayout, driver *enterprisebundle.Driver) error {
	receipts, err := driver.Store.Receipts()
	if err != nil {
		return err
	}
	pending := false
	for _, rc := range receipts {
		if rc.State == enterprisebundle.StateApplied {
			pending = true
			break
		}
	}
	if !pending {
		return syncWindowsBundleMarker(driver.Store)
	}
	installed, err := readBoundedConfigFile(layout.ConfigPath, windowsBundleMaxConfig)
	if err != nil {
		return err
	}
	confirmed, err := settleWindowsAppliedBundle(driver, installed, windowsBundlePolicy(ctx))
	if err != nil || !confirmed {
		return err
	}
	return syncWindowsBundleMarker(driver.Store)
}

// A crash between confirming the receipt and updating the MDM marker is
// repaired by the next status call, including when the receipt is already
// confirmed. Matching values do not cause a registry write.
func syncWindowsBundleMarker(store *enterprisebundle.Store) error {
	st, err := store.LoadState()
	if err != nil || st.Current == nil {
		return err
	}
	marker, err := registry.OpenKey(registry.LOCAL_MACHINE, WindowsEnterpriseMarkerKey,
		registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("open the enterprise marker to publish the confirmed bundle: %w", err)
	}
	defer marker.Close()
	id, _, idErr := marker.GetStringValue("BundleId")
	version, _, versionErr := marker.GetStringValue("BundleVersion")
	state, _, stateErr := marker.GetStringValue("BundleState")
	if idErr == nil && versionErr == nil && stateErr == nil &&
		id == st.Current.BundleID && version == strconv.FormatUint(st.Current.Version, 10) && state == enterprisebundle.StateConfirmed {
		return nil
	}
	return writeWindowsBundleMarker(marker)
}

// A status read may confirm only the exact config already installed and
// enforced. A failed health check leaves the receipt open for the normal
// lifecycle recovery, which can roll back through the ensure transaction.
func settleWindowsAppliedBundle(driver *enterprisebundle.Driver, installed []byte, policy *enterprisebundle.GatewayPolicy) (bool, error) {
	receipts, err := driver.Store.Receipts()
	if err != nil {
		return false, err
	}
	installedSHA := sha256HexBytes(installed)
	for _, rc := range receipts {
		if rc.State != enterprisebundle.StateApplied || rc.ConfigSHA256 != installedSHA || policy == nil ||
			!driver.TransactionApplied(rc, installedSHA, policy) || policy.EffectiveDigest != rc.EffectivePolicyDigest ||
			policy.Digest != rc.EffectivePolicyDigest {
			continue
		}
		if err := enterprisebundle.ConfirmPolicyDigests(rc.ExpectedDigest, policy.EffectiveDigest, policy.Digest, rc.DigestComparable); err == nil {
			_, err = driver.Store.Confirm(rc)
			if errors.Is(err, enterprisebundle.ErrConfirmationPrerequisiteMissing) {
				// The gateway proves the config, but a legacy receipt may have
				// lost its trust anchors. Status still reports it as applied.
				continue
			}
			return err == nil, err
		}
	}
	return false, nil
}

// windowsStagedBundleGeneration ties the installer child process's config
// generation to the receipt staged by the parent before Setup installs it.
func windowsStagedBundleGeneration(path string, raw []byte) (configwrite.Options, bool, error) {
	layout, err := windowsBundleLayout()
	if err != nil || !strings.EqualFold(filepath.Clean(path), filepath.Clean(layout.ConfigPath)) {
		return configwrite.Options{}, false, nil
	}
	return newWindowsBundleDriver(layout).ConfigGenerationOptions(raw)
}

// windowsBundleCurrent reports a current (confirmed) policy bundle in the
// Windows bundle store.
func windowsBundleCurrent() (bool, error) {
	layout, err := windowsBundleLayout()
	if err != nil {
		return false, nil
	}
	state, err := newWindowsBundleDriver(layout).Store.LoadState()
	if err != nil {
		return false, fmt.Errorf("read the policy bundle state: %w", err)
	}
	return state.Current != nil, nil
}

// windowsBundleRun is the bundle state of one ensure run.
type windowsBundleRun struct {
	ctx      context.Context
	layout   managed.StandaloneLayout
	driver   *enterprisebundle.Driver
	prepared *enterprisebundle.Prepared
	sessions *enterprisestatus.SessionRestartStatus
	// previous is the installed config.yaml before the run: the last good
	// config while no bundle is current.
	previous       []byte
	warnings       []enterprisebundle.Warning
	anchorStage    string
	anchorPath     string
	anchorPrevious []byte
	anchorExisted  bool
	// previousGeneration is config.generation.json as the run found it.
	previousGeneration configwrite.GenerationState
	// anchorOnly records the anchor file a TRUSTANCHORS= run without
	// BUNDLE= replaced, for the result (settleAnchorOnlyEnsure).
	anchorOnly *anchorOnlyChange
	// anchorCommit records the anchor file a BUNDLE= TRUSTANCHORS= run
	// committed (commitAnchors), so a repeat of the confirmed bundle that
	// installed other anchors is not reported as an already_applied no-op
	// (GAP-0034).
	anchorCommit *anchorOnlyChange
	// gatewayRestarted is set by the config apply path after it actually
	// restarts the gateway, and is copied into the shared receipt.
	gatewayRestarted bool
	// anchorReservation holds room for the change event of TRUSTANCHORS=;
	// anchorStaged is set while the anchors staged for the bundle wait for
	// commitAnchors, so a run that ends without committing them records one
	// refused anchor install (refuseStagedAnchors).
	anchorReservation *enterprisestatus.ChangeReservation
	anchorStaged      bool
	unlock            func()
	// stderr takes the warning of a reservation release that could not be
	// flushed (release runs after the result is printed).
	stderr io.Writer
}

// refuseStagedAnchors records one refused install, with code, of the trust
// anchors this run staged and did not commit. It does nothing once they
// were committed or recorded.
func (run *windowsBundleRun) refuseStagedAnchors(code string) error {
	if !run.anchorStaged {
		return nil
	}
	run.anchorStaged = false
	current, _ := safefile.ReadRegularFileBounded(run.anchorPath, windowsBundleMaxAnchors)
	return recordWindowsAnchorsFailure(run.layout, run.anchorReservation, code, false, current)
}

// windowsStagedAnchorsRefusalCode is the code of a bundle run that ended
// without committing its staged anchors: its first error, else the failure
// of its receipt, else not_confirmed.
func windowsStagedAnchorsRefusalCode(result *enterprisestatus.Result, p *enterprisebundle.Prepared) string {
	if len(result.Errors) > 0 {
		return result.Errors[0].Code
	}
	if p != nil && p.Receipt != nil && p.Receipt.ErrorCode != "" {
		return string(p.Receipt.ErrorCode)
	}
	return string(enterprisebundle.CodeNotConfirmed)
}

func (run *windowsBundleRun) release() {
	// A transaction can commit its config before Finish advances the receipt
	// from staged to applied. Preserve its anchors until settle classifies
	// the committed receipt, even when this run exits before Finish.
	pending := run.anchorReceiptPending()
	if !pending {
		_ = run.refuseStagedAnchors(string(enterprisebundle.CodeInterrupted))
	}
	warnChangeReleaseUnflushed(run.stderr, run.anchorReservation.Release())
	run.anchorReservation = nil
	if run.anchorStage != "" && !pending {
		_ = os.Remove(run.anchorStage)
		run.anchorStage = ""
		if run.prepared != nil && run.prepared.Receipt != nil {
			_ = cleanupWindowsReceiptAnchors(run.layout, run.prepared.Receipt)
		}
	}
	if run.unlock != nil {
		run.unlock()
		run.unlock = nil
	}
}

func (run *windowsBundleRun) anchorReceiptPending() bool {
	if run.prepared == nil || run.prepared.Receipt == nil || run.anchorStage == "" {
		return false
	}
	rc := run.prepared.Receipt
	if rc.State == enterprisebundle.StateApplied {
		return true
	}
	if rc.State != enterprisebundle.StateStaged {
		return false
	}
	installed, err := safefile.ReadRegularFileBounded(run.layout.ConfigPath, windowsBundleMaxConfig)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil || run.driver == nil {
		return true
	}
	committed, err := run.driver.CommittedPendingConfig(installed)
	return err != nil || committed != nil && committed.ReceiptID == rc.ReceiptID
}

func newWindowsBundleDriver(layout managed.StandaloneLayout) *enterprisebundle.Driver {
	store := enterprisebundle.NewStore(filepath.Join(layout.ConfigDir, enterprisebundle.BundlesDirName), layout.LifecycleDir)
	store.PrivateStage = windowsBundlePrivateStage
	store.EnsureStageDirectory = windowsBundleEnsureStageDirectory
	store.PublishStageFile = windowsBundlePublishStageFile
	store.SealVersion = windowsBundleSealVersion
	store.PublishVersion = windowsBundlePublishVersion
	store.PublishReceipt = windowsBundlePublishReceipt
	store.EnsurePublicReceiptEventsDirectory = ensureWindowsBundlePublicReceiptEventsDirectory
	store.EnsurePrivateDirectory = windowsBundleEnsurePrivateDirectory
	store.PublishPrivateFile = windowsBundlePublishPrivateFile
	store.ReceiptEventReported = func(id string) bool { return enterprisestatus.ReceiptEventReported(layout.DataDir, id) }
	store.BeforeConfirm = func(rc *enterprisebundle.Receipt) error {
		_, err := commitWindowsReceiptAnchors(layout, rc, nil)
		return err
	}
	store.AfterConfirm = func(rc *enterprisebundle.Receipt) error { return cleanupWindowsReceiptAnchors(layout, rc) }
	store.BeforeFail = func(rc *enterprisebundle.Receipt) error { return restoreFailedWindowsReceiptAnchors(layout, rc) }
	store.AfterFail = func(rc *enterprisebundle.Receipt) error { return cleanupWindowsReceiptAnchors(layout, rc) }
	return &enterprisebundle.Driver{
		Store:      store,
		ConfigPath: layout.ConfigPath,
		DeviceLayout: func() *enterprisebundle.DeviceLayout {
			device := enterprisebundle.DeviceLayoutFromManaged(layout)
			return &device
		}(),
		AnchorsPath: filepath.Join(layout.ConfigDir, "trust", enterprisebundle.AnchorsName),
		AnchorTrust: bundleAnchorTrust, Platform: enterprisebundle.PlatformWindows, ProductVersion: appVersion,
		SecretValue: bundleSecretValue, Digester: bundleDigester,
		TrustVersion: func(dir string) error {
			return windowsBundleTrust(filepath.Join(dir, enterprisebundle.ManifestName))
		},
	}
}

// privateWindowsBundleStage removes the service's inherited read access
// before the bundle files are copied into staging.
func privateWindowsBundleStage(root string) error {
	return applyWindowsBundleSDDL(root, windowsBundlePrivateSDDL())
}

// createWindowsBundleDirectory gives a new directory its final protected
// descriptor in CreateDirectory. Existing directories owned by Administrators
// or the elevated caller are opened without following reparse points and
// repaired through that handle when their descriptor is not exact.
func createWindowsBundleDirectory(path, sddl string) error {
	if err := winpath.RejectReparseChain(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return err
	}
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		descriptor, descriptorErr := windows.SecurityDescriptorFromString(sddl)
		if descriptorErr != nil {
			return descriptorErr
		}
		name, nameErr := winpath.UTF16Ptr(path)
		if nameErr != nil {
			return nameErr
		}
		attributes := &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		}
		if createErr := windows.CreateDirectory(name, attributes); createErr != nil {
			if !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
				return createErr
			}
		}
	} else if err != nil {
		return err
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return err
	}
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("bundle directory is not a regular directory: %s", path)
	}
	securityInfo := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityInfo)
	if err != nil {
		return err
	}
	actualOwner, _, err := actual.Owner()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if !windowsEnterpriseSIDEqual(actualOwner, owner) {
		// An older publisher may have left a directory owned by the
		// elevated account (or SYSTEM) that created it. Only that same
		// principal may migrate it to the Administrators-owned descriptor.
		if !windowsEnterpriseIsElevated() {
			return fmt.Errorf("bundle directory has an unexpected owner: %s", path)
		}
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return err
		}
		if user == nil || !windowsEnterpriseSIDEqual(actualOwner, user.User.Sid) {
			return fmt.Errorf("bundle directory has an unexpected owner: %s", path)
		}
	}
	matches, err := windowsEnterpriseExactDescriptorMatch(actual, descriptor)
	if err != nil {
		return err
	}
	if matches {
		return nil
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, group, dacl, nil); err != nil {
		return err
	}
	actual, err = windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityInfo)
	if err != nil {
		return err
	}
	matches, err = windowsEnterpriseExactDescriptorMatch(actual, descriptor)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("bundle directory descriptor differs after repair: %s", path)
	}
	return nil
}

func ensureWindowsBundlePrivateDirectory(path string) error {
	if filepath.Base(path) == enterprisebundle.ReceiptsDirName {
		if err := ensureWindowsBundlePrivateDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return createWindowsBundleDirectory(path, windowsBundlePrivateSDDL())
}

func ensureWindowsBundleStageDirectory(root, path string) error {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("staging directory escapes bundle root: %s", path)
	}
	if relative == "." {
		return createWindowsBundleDirectory(root, windowsBundlePrivateSDDL())
	}
	if err := createWindowsBundleDirectory(root, windowsBundlePrivateSDDL()); err != nil {
		return err
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		if err := createWindowsBundleDirectory(current, windowsBundlePrivateSDDL()); err != nil {
			return err
		}
	}
	return nil
}

func publishWindowsBundlePrivateFile(path string) error {
	return applyWindowsBundleSDDL(path, windowsBundleAdminFileSDDL())
}

func publishWindowsBundleReceipt(path string) error {
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	if filepath.Base(filepath.Dir(path)) == enterprisestatus.PublicReceiptEventsDirName {
		name := filepath.Base(path)
		if !strings.HasSuffix(name, ".json") ||
			!enterprisestatus.ValidReceiptID(strings.TrimSuffix(name, ".json")) {
			return fmt.Errorf("invalid public receipt event name: %s", name)
		}
		if err := createWindowsBundleDirectory(filepath.Dir(path), windowsBundleDirectorySDDL(service.String())); err != nil {
			return err
		}
		return applyWindowsBundleSDDL(path, windowsBundleReceiptSDDL(service.String()))
	}
	return applyWindowsBundleSDDL(path, windowsBundleReceiptSDDL(service.String()))
}

// applyWindowsBundleSDDL sets the full owner, group, and protected DACL so
// bundle paths agree with Setup's exact managed-path descriptors.
func applyWindowsBundleSDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	group, _, err := sd.Group()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, group, dacl, nil)
}

func ensureWindowsBundleDirectory(layout managed.StandaloneLayout) error {
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	sddl := windowsBundleDirectorySDDL(service.String())
	path := filepath.Join(layout.ConfigDir, enterprisebundle.BundlesDirName)
	if err := createWindowsBundleDirectory(path, sddl); err != nil {
		return err
	}
	return ensureWindowsBundleReceiptEvents(path, service.String())
}

func ensureWindowsBundleReceiptEvents(path, serviceSID string) error {
	// A previous build may have left the public spool administrator-only.
	// Repair it before Setup's first apply and exact-ACL verification.
	events := filepath.Join(path, enterprisestatus.PublicReceiptEventsDirName)
	if err := createWindowsBundleDirectory(events, windowsBundleDirectorySDDL(serviceSID)); err != nil {
		return err
	}
	entries, err := os.ReadDir(events)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("bundle receipt event is not a regular file: %s", entry.Name())
		}
		file := filepath.Join(events, entry.Name())
		if err := winpath.RejectReparseChain(file); err != nil {
			return err
		}
		// Only terminal receipt IDs are public. Unknown files retain the
		// verifier's AdminFile descriptor.
		sddl := windowsBundleAdminFileSDDL()
		if strings.HasSuffix(entry.Name(), ".json") &&
			enterprisestatus.ValidReceiptID(strings.TrimSuffix(entry.Name(), ".json")) {
			sddl = windowsBundleReceiptSDDL(serviceSID)
		}
		if err := applyWindowsBundleSDDL(file, sddl); err != nil {
			return err
		}
	}
	return nil
}

func ensureWindowsBundlePublicReceiptEventsDirectory(path string) error {
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	return createWindowsBundleDirectory(path, windowsBundleDirectorySDDL(service.String()))
}

// sealWindowsBundleVersionAssets grants the gateway service SID read and
// execute on each verified asset. The staging root stays administrator-only
// until the rename has published it as a version directory.
func sealWindowsBundleVersionAssets(root string) error {
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular bundle asset", path)
		}
		if err := applyWindowsBundleSDDL(path, windowsBundleVersionSDDL(service.String(), entry.IsDir())); err != nil {
			return err
		}
		mode := os.FileMode(0o444)
		if entry.IsDir() {
			mode = 0o555
		}
		return os.Chmod(path, mode)
	})
}

func publishWindowsBundleVersion(root string) error {
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	if err := applyWindowsBundleSDDL(root, windowsBundleVersionSDDL(service.String(), true)); err != nil {
		return err
	}
	return os.Chmod(root, 0o555)
}

// recordWindowsEarlyAnchorsRefusal records one refused anchor install for
// a TRUSTANCHORS= run refused over its arguments, before the bundle lock,
// on an installed computer. A computer that is not installed records
// nothing, as Linux and macOS refuse such a device before they record, and
// so does a caller that is not elevated (recordWindowsChange).
func recordWindowsEarlyAnchorsRefusal(cmd *cobra.Command, opts *windowsEnterpriseLifecycleOptions, code string) {
	// Only an elevated caller on an installed computer records into the
	// administrator-only change spool (r104 W5b: a fresh or unelevated run
	// creates no installed-host audit).
	if opts.trustAnchors == "" || !opts.installedBeforeRun || !windowsSecretIsElevated() {
		return
	}
	layout, err := windowsBundleLayout()
	if err != nil {
		warnChangeUnrecorded(cmd.ErrOrStderr(), err)
		return
	}
	current, _ := safefile.ReadRegularFileBounded(newWindowsBundleDriver(layout).AnchorsPath, windowsBundleMaxAnchors)
	warnChangeUnrecorded(cmd.ErrOrStderr(), recordWindowsAnchorsFailure(layout, nil, code, false, current))
}

// prepareWindowsEnterpriseBundle runs before the lifecycle reads --config.
// With --bundle it prepares the bundle and makes its rendered config the
// --config of the run. --trust-anchors with --bundle stages the anchor
// file and verifies the bundle against the stage; finish commits it once
// the bundle is confirmed. --trust-anchors alone installs the anchor file.
// In bundle mode (anchors installed) a --config that is not the
// current bundle config is refused with bundle_required. Without --bundle
// and --trust-anchors, a changing run on an installed device settles the
// receipts a killed bundle run left (settleWindowsInterruptedBundles). done
// is set when the run ended here with err as its outcome.
func prepareWindowsEnterpriseBundle(ctx context.Context, cmd *cobra.Command, action string, opts *windowsEnterpriseLifecycleOptions) (done bool, err error) {
	if opts.bundleRollback {
		return false, nil
	}
	requested := opts.bundlePath != "" || opts.trustAnchors != ""
	floorSource := ""
	refuse := func(code, message string) (bool, error) {
		return true, writeWindowsBundleRefusal(cmd, action, opts, code, message, floorSource)
	}
	// A TRUSTANCHORS= request an installed computer refuses over its
	// arguments records one refused anchor install, as every later refusal
	// does (refuseAnchors).
	refuseArguments := func(code, message string) (bool, error) {
		recordWindowsEarlyAnchorsRefusal(cmd, opts, code)
		return refuse(code, message)
	}
	if opts.refuseCapabilityLoss && opts.bundlePath == "" {
		return refuseArguments("invalid_arguments", "--refuse-capability-loss requires --bundle")
	}
	if requested && action != "ensure" {
		return refuseArguments("invalid_arguments", "--bundle and --trust-anchors are valid only with ensure")
	}
	if opts.bundlePath != "" && strings.TrimSpace(opts.configPath) != "" {
		return refuseArguments("invalid_arguments", "BUNDLE= (--bundle) cannot be combined with CONFIG= (--config): the signed bundle carries the config")
	}
	if opts.trustAnchors != "" && strings.TrimSpace(opts.configPath) != "" {
		// Installing the anchors puts the computer in bundle mode, which
		// refuses CONFIG=; installing them first would let this one run
		// apply an unsigned config past that check.
		// The code is bundle_required, as for a CONFIG= on a computer
		// already in bundle mode; the exit stays 1639, because the command
		// line itself can never succeed (#1288).
		code := string(enterprisebundle.CodeBundleRequired)
		recordWindowsEarlyAnchorsRefusal(cmd, opts, code)
		return true, writeWindowsBundleRefusalWithExit(cmd, action, opts, code,
			"TRUSTANCHORS= (--trust-anchors) cannot be combined with CONFIG= (--config): with trust anchors installed the computer takes its policy only from signed bundles; deliver BUNDLE= with TRUSTANCHORS=",
			floorSource, enterprisestatus.WindowsExitInvalidArgs)
	}
	if !windowsEnterpriseMutationAction(action) {
		return false, nil
	}
	layout, err := windowsBundleLayout()
	if err != nil {
		if requested {
			return refuse(string(enterprisebundle.CodeStateInvalid), "cannot resolve the standalone layout: "+err.Error())
		}
		return false, nil
	}
	driver := newWindowsBundleDriver(layout)
	if !requested {
		if done, err := refuseWindowsBundleRequired(cmd, action, opts, driver); done {
			return true, err
		}
		if opts.installedBeforeRun {
			// The bundle restore of this run (or the current bundle config it
			// was given) re-installs the last good bundle over a bundle config
			// a killed run installed and the gateway never confirmed.
			reinstall := windowsBundleRestoreRequested(action, opts) || strings.TrimSpace(opts.configPath) != ""
			opts.bundleSettle = &windowsBundleSettle{ctx: ctx}
			settleWindowsInterruptedBundles(opts.bundleSettle, layout, driver, opts.bundleLockWait, reinstall)
		}
		return false, nil
	}
	if !opts.installedBeforeRun {
		return refuse(string(enterprisebundle.CodeNotManaged), "DefenseClaw enterprise is not installed: install it first with /ensure CONFIG=<config.yaml>, then deliver policy bundles with /ensure BUNDLE=<file> TRUSTANCHORS=<bundle-anchors.json>")
	}
	// From here a refused TRUSTANCHORS= run records one refused anchor
	// install, as Linux and macOS do; once the install runs it records its
	// own outcome.
	// The same holds for a refusal after the anchors were staged for the
	// bundle: they are not installed.
	anchorPath := driver.AnchorsPath
	anchorRefusalPending := opts.trustAnchors != ""
	var run *windowsBundleRun
	refuseAnchors := func(code, message string) (bool, error) {
		if anchorRefusalPending {
			anchorRefusalPending = false
			var reservation *enterprisestatus.ChangeReservation
			if run != nil {
				reservation = run.anchorReservation
			}
			current, _ := safefile.ReadRegularFileBounded(anchorPath, windowsBundleMaxAnchors)
			warnChangeUnrecorded(cmd.ErrOrStderr(), recordWindowsAnchorsFailure(layout, reservation, code, false, current))
		}
		return refuse(code, message)
	}
	unlock, err := lockWindowsBundleStoreWithin(ctx, layout.LifecycleDir, opts.bundleLockWait)
	if err != nil {
		return refuseAnchors("lifecycle_busy", err.Error())
	}
	run = &windowsBundleRun{ctx: ctx, layout: layout, driver: driver, unlock: unlock, stderr: cmd.ErrOrStderr()}
	opts.bundle = run
	// Prepare owns the lock until it hands the run to the lifecycle caller.
	// A refusal may print a result before returning, but cannot transfer it.
	handedOff := false
	defer func() {
		if !handedOff {
			run.release()
		}
	}()
	if err := windowsBundleEnsureDirectory(layout); err != nil {
		return refuseAnchors(string(enterprisebundle.CodeStateInvalid), "cannot protect the policy bundle directory: "+err.Error())
	}
	if opts.trustAnchors != "" {
		// An install this computer could not audit is not made: the spool
		// must hold room for its change event before the file is written,
		// until the event is written.
		reservation, err := reserveWindowsChange(layout, enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, "")
		if err != nil {
			return refuseAnchors(string(enterprisebundle.CodeStateInvalid), "cannot record the trust anchor change: "+err.Error())
		}
		run.anchorReservation = reservation
		if opts.bundlePath != "" {
			run.anchorPath = anchorPath
			run.anchorStage = filepath.Join(layout.LifecycleDir, windowsBundleStagedAnchorsName)
			previous, readErr := safefile.ReadRegularFileBounded(anchorPath, windowsBundleMaxAnchors)
			if readErr == nil {
				run.anchorPrevious, run.anchorExisted = previous, true
			} else if !errors.Is(readErr, fs.ErrNotExist) {
				return refuseAnchors(string(enterprisebundle.CodeStateInvalid), "cannot read the installed trust anchors: "+readErr.Error())
			}
			driver.AnchorsPath = run.anchorStage
		} else {
			// The install below replaces the file as before; an unreadable
			// one only counts as changed (previous nil).
			previous, readErr := safefile.ReadRegularFileBounded(anchorPath, windowsBundleMaxAnchors)
			run.anchorOnly = &anchorOnlyChange{path: anchorPath, existed: !errors.Is(readErr, fs.ErrNotExist), previous: previous}
		}
		anchorRefusalPending = false
		installed, replaced, err := installWindowsBundleAnchors(opts.trustAnchors, driver.AnchorsPath)
		if err != nil {
			code := string(windowsBundleCode(err, enterprisebundle.CodeAnchorInsecure))
			failed := code == string(enterprisebundle.CodeStateInvalid)
			message := "the trust anchors were not installed: " + err.Error()
			if replaced && run.anchorOnly != nil {
				// The installed file was replaced and then failed its
				// check: the previous file is put back, as Linux and macOS
				// do, and the change is recorded as failed with the file
				// left installed, never as refused.
				failed = true
				if restoreErr := restoreWindowsBundleAnchors(anchorPath, run.anchorOnly.existed, run.anchorOnly.previous); restoreErr != nil {
					code = "anchor_restore_failed"
					message += "; the previous trust anchors could not be put back: " + restoreErr.Error()
				} else {
					message += "; the previous trust anchors were put back"
				}
			}
			current, _ := safefile.ReadRegularFileBounded(anchorPath, windowsBundleMaxAnchors)
			warnChangeUnrecorded(cmd.ErrOrStderr(), recordWindowsAnchorsFailure(layout, run.anchorReservation, code, failed, current))
			return refuse(code, message)
		}
		if run.anchorOnly != nil {
			run.anchorOnly.installed = installed
			if err := recordWindowsAnchorsChange(layout, run.anchorReservation, run.anchorOnly); err != nil {
				run.warnings = append(run.warnings, changeUnrecordedWarning(err))
			}
		} else {
			// Staged for the bundle: until finish commits them, a refusal
			// of this run records one refused anchor install.
			anchorRefusalPending = true
		}
	}
	if opts.bundlePath == "" {
		handedOff = true
		return false, nil
	}
	installed, readConfigErr := readBoundedConfigFile(layout.ConfigPath, windowsBundleMaxConfig)
	if readConfigErr != nil && !errors.Is(readConfigErr, fs.ErrNotExist) {
		return refuseAnchors(string(enterprisebundle.CodeStateInvalid), "cannot read the enforced config: "+readConfigErr.Error())
	}
	run.previous = installed
	run.previousGeneration, _ = configwrite.ReadGenerationState(layout.ConfigPath)
	driver.EnforcedConfig = installed
	driver.RefuseCapabilityLoss = opts.refuseCapabilityLoss
	if opts.deferRestart {
		driver.RefuseRestart = windowsBundleRestartDeferral
	}
	driver.DeliveryID = opts.bundleDeliveryID
	report, rollback, err := driver.SettleRun(installed, windowsBundlePolicy(ctx))
	if err != nil {
		return refuseAnchors(string(enterprisebundle.CodeStateInvalid), "cannot settle the earlier bundle receipts: "+err.Error()+
			"; nothing was failed or rolled back: run the same command again")
	}
	if n := len(report.Pending); n > 0 {
		run.warnings = append(run.warnings, enterprisebundle.Warning{Code: enterprisebundle.WarnBundlePending,
			Message: fmt.Sprintf(windowsBundlePendingMessage, n)})
	}
	if len(report.Interrupted) > 0 {
		run.warnings = append(run.warnings, enterprisebundle.Warning{Code: string(enterprisebundle.CodeInterrupted),
			Message: fmt.Sprintf("%d earlier bundle run(s) ended before they applied; the last good bundle kept enforcing", len(report.Interrupted))})
	}
	if len(rollback) > 0 {
		// The installed config is a bundle that was never confirmed, not a
		// last good config: a rollback of this run must not report it as one.
		run.previous, run.previousGeneration = nil, configwrite.GenerationState{}
		run.warnings = append(run.warnings, enterprisebundle.Warning{Code: string(enterprisebundle.CodeNotConfirmed),
			Message: "an earlier bundle was installed but never confirmed; this run installs the new bundle over it"})
	}
	b, readErr := readBundleInput(opts.bundlePath)
	prepared, err := driver.Prepare(ctx, b, readErr)
	run.prepared = prepared
	if prepared != nil {
		floorSource = prepared.FloorSource
		run.warnings = append(run.warnings, prepared.Warnings...)
	}
	if err != nil {
		return refuseAnchors(string(windowsBundleCode(err, enterprisebundle.CodeApplyFailed)), windowsBundleNotApplied(prepared, err.Error(), windowsBundleHasCurrent(driver.Store)))
	}
	if prepared.Receipt != nil && run.anchorStage != "" {
		if err := run.bindReceiptAnchors(); err != nil {
			_ = driver.Store.Fail(prepared.Receipt, enterprisebundle.CodeStateInvalid, "cannot retain the verified trust anchors for this receipt")
			return refuseAnchors(string(enterprisebundle.CodeStateInvalid), "cannot retain the verified trust anchors for this receipt: "+err.Error())
		}
		id := prepared.Receipt.ReceiptID
		driver.Store.BeforeConfirm = func(rc *enterprisebundle.Receipt) error {
			reservation := (*enterprisestatus.ChangeReservation)(nil)
			if rc.ReceiptID == id {
				reservation = run.anchorReservation
			}
			change, err := commitWindowsReceiptAnchors(layout, rc, reservation)
			if err == nil && rc.ReceiptID == id {
				run.anchorCommit = change
			}
			return err
		}
	}
	path := filepath.Join(layout.LifecycleDir, windowsBundleConfigName)
	if err := writeWindowsBundleAdminFile(path, prepared.Config); err != nil {
		if prepared.Receipt != nil {
			_ = driver.Store.Fail(prepared.Receipt, enterprisebundle.CodeApplyFailed, "cannot write the rendered bundle config")
		}
		return refuseAnchors(string(enterprisebundle.CodeApplyFailed), "cannot write the rendered bundle config: "+err.Error())
	}
	opts.configPath = path
	// finish (or release) records the staged anchors from here.
	run.anchorStaged = anchorRefusalPending
	handedOff = true
	return false, nil
}

// windowsBundleSettle is what a changing run that delivers no bundle
// settled of the receipts a killed bundle run left. The bundle status
// warning bundle_pending and the contract (4.6) name a plain `enterprise
// windows ensure` as the recovery, so it settles them as `ensure --bundle`
// does before it receives its own bundle (GAP-1302).
type windowsBundleSettle struct {
	ctx      context.Context
	warnings []enterprisebundle.Warning
	// deferred is set while an install transaction is pending: the ensure
	// recovers it first, and finish settles the receipts after it.
	deferred bool
	// replacing names the bundle a killed run installed and the gateway
	// never confirmed; the bundle restore of this run replaces its config
	// with the confirmed bundle's.
	replacing string
}

func (s *windowsBundleSettle) warn(code, message string) {
	s.warnings = append(s.warnings, enterprisebundle.Warning{Code: code, Message: message})
}

// windowsBundleSettleReplacing is the bundle the restore of this run
// replaces (windowsBundleSettle.replacing), or "".
func windowsBundleSettleReplacing(opts *windowsEnterpriseLifecycleOptions) string {
	if opts == nil || opts.bundleSettle == nil {
		return ""
	}
	return opts.bundleSettle.replacing
}

// windowsBundleInstallTransactionPending reports an install transaction a
// run started and did not finish (install\pending.json): its recovery puts
// back the config it recorded.
func windowsBundleInstallTransactionPending(layout managed.StandaloneLayout) bool {
	_, err := os.Lstat(filepath.Join(filepath.Dir(layout.ConfigDir), "install", "pending.json"))
	return err == nil
}

// settleWindowsInterruptedBundles settles, under bundle.lock, the receipts
// no run finished: received, verified and staged receipts fail as
// interrupted (nothing was installed), and an applied one (or a staged one
// whose config a committed transaction installed) is confirmed when the
// installed config and the gateway enforce it and fails as not_confirmed
// otherwise (warning bundle_unconfirmed). reinstall says whether this run
// then re-installs the last good bundle over a config that failed that way;
// the warning says who does.
// While a live bundle run holds the lock it owns its receipts, and nothing is
// settled. While an install transaction is pending, the settle waits for the
// ensure to recover it (finishWindowsInterruptedBundles runs it again).
func settleWindowsInterruptedBundles(settle *windowsBundleSettle, layout managed.StandaloneLayout, driver *enterprisebundle.Driver, wait time.Duration, reinstall bool) {
	unsettled, err := driver.Store.Unsettled()
	if err != nil {
		settle.warn(windowsBundleStateUnreadableWarning, "could not read the policy bundle receipts to settle them: "+err.Error())
		return
	}
	if len(unsettled) == 0 {
		settle.deferred = false
		return
	}
	if windowsBundleInstallTransactionPending(layout) {
		settle.deferred = true
		return
	}
	settle.deferred = false
	unlock, err := lockWindowsBundleStoreWithin(settle.ctx, layout.LifecycleDir, wait)
	if err != nil {
		if !errors.Is(err, errWindowsBundleStoreBusy) {
			settle.warn(windowsBundleStateUnreadableWarning, "could not lock the policy bundle store to settle the receipts a killed run left: "+err.Error())
		}
		return
	}
	defer unlock()
	installed, err := readBoundedConfigFile(layout.ConfigPath, windowsBundleMaxConfig)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		settle.warn(windowsBundleStateUnreadableWarning, "could not read the installed config to settle the policy bundle receipts a killed run left: "+err.Error())
		return
	}
	report, rollback, err := driver.SettleRun(installed, windowsBundlePolicy(settle.ctx))
	if err != nil {
		settle.warn(windowsBundleStateUnreadableWarning, "could not settle the policy bundle receipts a killed run left: "+err.Error())
		return
	}
	if n := len(report.Interrupted); n > 0 {
		settle.warn(windowsBundleInterruptedWarning, fmt.Sprintf(
			"%d policy bundle(s) a previous run received were not applied (failed: interrupted); the last good bundle keeps enforcing", n))
	}
	if n := len(report.Pending); n > 0 {
		settle.warn(enterprisebundle.WarnBundlePending, fmt.Sprintf(windowsBundlePendingMessage, n))
	}
	if n := len(report.Completed); n > 0 {
		settle.warn(enterprisebundle.WarnConfirmedAfterInterrupt, fmt.Sprintf(
			"%d policy bundle(s) a previous run applied and did not confirm are confirmed now: the gateway enforces them", n))
	}
	if len(rollback) > 0 {
		rc := rollback[0]
		label := fmt.Sprintf("policy bundle %s version %d", rc.BundleID, rc.Version)
		message := fmt.Sprintf("%s was applied by a run that ended before the gateway confirmed it (failed: %s); ", label, rc.ErrorCode)
		switch {
		case !windowsBundleHasCurrent(driver.Store):
			message += "no bundle was confirmed before it, so its config stays installed until a signed bundle is delivered and confirmed"
		case reinstall:
			settle.replacing = label
			message += "this run re-installs the last good bundle"
		default:
			message += "run `enterprise windows ensure --profile standalone` to re-install the last good bundle"
		}
		settle.warn(windowsBundleUnconfirmedWarning, message)
	}
	if err := windowsBundleSyncMarker(driver.Store); err != nil {
		settle.warn(windowsBundleMarkerFailedWarning, "the policy bundle receipts were settled, but the enterprise marker was not updated: "+err.Error())
	}
}

// finishWindowsInterruptedBundles adds what settleWindowsInterruptedBundles
// did to the result. A settle deferred behind a pending install transaction
// runs now, after the ensure recovered it.
func finishWindowsInterruptedBundles(opts *windowsEnterpriseLifecycleOptions, result *enterprisestatus.Result) {
	settle := opts.bundleSettle
	if settle == nil {
		return
	}
	opts.bundleSettle = nil
	if settle.deferred {
		if layout, err := windowsBundleLayout(); err == nil {
			settleWindowsInterruptedBundles(settle, layout, newWindowsBundleDriver(layout), opts.bundleLockWait, false)
		}
		if settle.deferred {
			settle.warn(windowsBundleSettleDeferredWarning, "an install transaction is still pending, so the policy bundle receipts a killed run left were not settled; "+
				"the current or last good bundle keeps enforcing: run `enterprise windows ensure --profile standalone` again")
		}
	}
	for _, w := range settle.warnings {
		result.AddWarning(w.Code, w.Message)
	}
}

// refuseWindowsBundleRequired refuses, in bundle mode, a --config that is
// not the config of the current bundle.
func refuseWindowsBundleRequired(cmd *cobra.Command, action string, opts *windowsEnterpriseLifecycleOptions, driver *enterprisebundle.Driver) (bool, error) {
	if strings.TrimSpace(opts.configPath) == "" {
		return false, nil
	}
	bundleMode, modeErr := windowsBundleMode(driver)
	if modeErr != nil {
		return true, writeWindowsBundleRefusal(cmd, action, opts, string(enterprisebundle.CodeStateInvalid),
			"cannot read policy bundle state before applying CONFIG=: "+modeErr.Error(), "")
	}
	if !bundleMode {
		return false, nil
	}
	current, _, err := driver.CurrentConfig()
	given, readErr := readBoundedConfigFile(opts.configPath, windowsBundleMaxConfig)
	if err == nil && readErr == nil && current != nil && bytes.Equal(given, current) {
		return false, nil
	}
	return true, writeWindowsBundleRefusal(cmd, action, opts, string(enterprisebundle.CodeBundleRequired), fmt.Sprintf(
		"this device takes its policy from signed bundles (trust anchors are held at %s), so CONFIG= is not applied; deliver a signed bundle with /ensure BUNDLE=<file>",
		driver.AnchorsPath), "")
}

func windowsBundleMode(driver *enterprisebundle.Driver) (bool, error) {
	if _, err := os.Lstat(driver.AnchorsPath); err == nil {
		return true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	state, err := driver.Store.LoadState()
	if err != nil {
		return false, err
	}
	if state.Current != nil {
		return true, nil
	}
	unsettled, err := driver.Store.Unsettled()
	return len(unsettled) != 0, err
}

// writeWindowsBundleRefusal answers a bundle run that ended before the
// transaction: nothing was installed, so the result is the host as it is
// with the bundle block of the receipt.
func writeWindowsBundleRefusal(cmd *cobra.Command, action string, opts *windowsEnterpriseLifecycleOptions, code, message, floorSource string) error {
	return writeWindowsBundleRefusalWithExit(cmd, action, opts, code, message, floorSource, 0)
}

// writeWindowsBundleRefusalWithExit is writeWindowsBundleRefusal with an
// explicit exit code; 0 derives it from the error code.
func writeWindowsBundleRefusalWithExit(cmd *cobra.Command, action string, opts *windowsEnterpriseLifecycleOptions, code, message, floorSource string, exit int) error {
	result := newWindowsEnterpriseStandaloneResult(action, opts)
	applyWindowsEnterpriseRecordedDeployment(result)
	result.FloorSource = floorSource
	result.AddError(code, message)
	if exit == 0 {
		exit = windowsEnterpriseFailureCodeFor(result)
	}
	return finishWindowsEnterpriseStandalone(cmd, opts, result, exit)
}

func windowsBundleCode(err error, fallback enterprisebundle.Code) enterprisebundle.Code {
	if code := enterprisebundle.CodeOf(err); code != "" {
		return code
	}
	return fallback
}

func windowsBundleHasCurrent(store *enterprisebundle.Store) bool {
	state, err := store.LoadState()
	return err == nil && state.Current != nil
}

func windowsBundleNotApplied(p *enterprisebundle.Prepared, message string, hasCurrent bool) string {
	policy := "the device remains on its base policy"
	if hasCurrent {
		policy = "the last good policy keeps enforcing"
	}
	if p == nil || p.Receipt == nil || p.Receipt.BundleID == "" {
		return "the policy bundle was not applied: " + message + "; " + policy
	}
	return fmt.Sprintf("policy bundle %s version %d was not applied: %s; %s",
		p.Receipt.BundleID, p.Receipt.Version, message, policy)
}

// finishWindowsEnterpriseBundle settles the bundle of a run once its ensure
// ended, before the result is recorded and printed: the bundle is confirmed
// when the transaction installed its config and the gateway enforces it;
// a committed config whose gateway cannot answer stays applied and pending;
// a rejected or uncommitted candidate is restored and failed. Every
// standalone result then carries the bundle block.
func finishWindowsEnterpriseBundle(cmd *cobra.Command, opts *windowsEnterpriseLifecycleOptions, result *enterprisestatus.Result) {
	if opts == nil || opts.bundleRollback {
		return
	}
	run := opts.bundle
	if run == nil {
		finishWindowsInterruptedBundles(opts, result)
		attachWindowsBundleSummary(result, nil, nil, nil)
		return
	}
	opts.bundle = nil
	defer run.release()
	for _, w := range run.warnings {
		result.AddWarning(w.Code, w.Message)
	}
	p := run.prepared
	if p != nil && p.AlreadyApplied && len(result.Errors) == 0 && result.Noop {
		result.NoopReason = "already_applied"
	}
	if p != nil && p.Receipt != nil && !enterprisebundle.Finished(p.Receipt.State) {
		sessions := platformBundleSessionStatus(run.ctx)
		run.sessions = &sessions
		recordWindowsBundleSessions(p.Receipt, sessions)
		installed := windowsBundleInstalledSHA(run.layout.ConfigPath)
		var failure []string
		for _, e := range result.Errors {
			failure = append(failure, e.Code)
		}
		policy := enterprisebundle.GatewayPolicy{}
		for i := 0; len(failure) == 0 && installed == p.ConfigSHA256 && i <= windowsBundlePolicyWaits; i++ {
			if i > 0 {
				windowsBundleSleep(5 * time.Second)
			}
			if next := windowsBundlePolicy(run.ctx); next != nil {
				policy = *next
			}
			if windowsBundleEnforces(policy) && run.driver.TransactionApplied(p.Receipt, installed, &policy) {
				break
			}
		}
		_, err := run.driver.Finish(p, installed, failure, policy, run.gatewayRestarted, func() (string, bool) {
			if windowsBundleRollbackDeadlineExpired(run.ctx, p.Receipt, result) {
				return "", false
			}
			return rollbackWindowsBundle(cmd, opts, run)
		})
		if err != nil {
			code := string(windowsBundleCode(err, enterprisebundle.CodeApplyFailed))
			switch {
			case windowsBundleHasCode(result.Errors, code):
			case p.Receipt.State == enterprisebundle.StateApplied:
				// A proven live policy whose confirmation record failed, or a
				// committed config whose gateway is down, stays applied for the
				// next run. Neither is a failed delivery.
				result.AddError(code, fmt.Sprintf("policy bundle %s version %d: %s", p.Receipt.BundleID, p.Receipt.Version, err.Error()))
			default:
				result.AddError(code, windowsBundleNotApplied(p, err.Error(), windowsBundleHasCurrent(run.driver.Store)))
			}
		}
		if p.Receipt.State == enterprisebundle.StateApplied {
			result.AddWarning(enterprisebundle.WarnBundlePending,
				"the signed bundle config is installed but its receipt is not confirmed yet; retry ensure to finish confirmation")
		}
		// An applied receipt retains its private anchors for the next settle.
		// The store commits them before writing a confirmed state.
		if p.Receipt.State == enterprisebundle.StateApplied || p.Receipt.State == enterprisebundle.StateConfirmed {
			run.anchorStaged = false
		}
	}
	if p != nil && p.AlreadyApplied && len(result.Errors) == 0 && run.anchorStage != "" {
		run.commitAnchors(result)
	}
	if err := run.refuseStagedAnchors(windowsStagedAnchorsRefusalCode(result, p)); err != nil {
		warning := changeUnrecordedWarning(err)
		result.AddWarning(warning.Code, warning.Message)
	}
	var receipt *enterprisebundle.Receipt
	if p != nil {
		receipt = p.Receipt
	}
	if p != nil && p.AlreadyApplied && result.Bundle == nil {
		// A repeated delivery of the current bundle wrote no receipt: its
		// block is the confirmed current bundle, not a newer delivery that
		// failed after staging (the store summary).
		if current, err := run.driver.Store.CurrentSummary(); err == nil && current != nil {
			result.Bundle = current
		}
	}
	confirmed := attachWindowsBundleSummary(result, run.driver.Store, receipt, run.sessions)
	settleAnchorOnlyEnsure(result, run.anchorOnly, confirmed)
	// The bundle of this run verified against the committed anchors, so the
	// change line needs no clause about the confirmed bundle.
	settleAnchorOnlyEnsure(result, run.anchorCommit, false)
}

func recordWindowsBundleSessions(receipt *enterprisebundle.Receipt, sessions enterprisestatus.SessionRestartStatus) {
	receipt.SessionsRestartRequired = sessions.Count
	if sessions.State == "unknown" {
		receipt.WarningCodes = append(receipt.WarningCodes, "sessions_scan_unknown")
	}
}

// commitAnchors installs the staged trust anchors of a confirmed bundle and
// records what it installed for the result; a failed commit puts the
// previous anchors back and fails the run.
func (run *windowsBundleRun) commitAnchors(result *enterprisestatus.Result) {
	run.anchorStaged = false // The commit records its own outcome.
	installed, _, err := installWindowsBundleAnchors(run.anchorStage, run.anchorPath)
	if err != nil {
		result.AddError("anchor_install_failed", "could not commit the verified trust anchors: "+err.Error())
		code := "anchor_install_failed"
		if restoreErr := restoreWindowsBundleAnchors(run.anchorPath, run.anchorExisted, run.anchorPrevious); restoreErr != nil {
			result.AddError("anchor_restore_failed", "could not restore the previous trust anchors: "+restoreErr.Error())
			code = "anchor_restore_failed"
		}
		current, _ := safefile.ReadRegularFileBounded(run.anchorPath, windowsBundleMaxAnchors)
		if err := recordWindowsAnchorsFailure(run.layout, run.anchorReservation, code, true, current); err != nil {
			warning := changeUnrecordedWarning(err)
			result.AddWarning(warning.Code, warning.Message)
		}
		return
	}
	run.anchorCommit = &anchorOnlyChange{path: run.anchorPath, existed: run.anchorExisted, previous: run.anchorPrevious, installed: installed}
	if err := recordWindowsAnchorsChange(run.layout, run.anchorReservation, run.anchorCommit); err != nil {
		warning := changeUnrecordedWarning(err)
		result.AddWarning(warning.Code, warning.Message)
	}
}

// restoreWindowsBundleAnchors puts the anchor file a run replaced back at
// path: previous when a file existed, no file when none did. A file that
// existed and could not be read (previous nil) cannot be put back.
func restoreWindowsBundleAnchors(path string, existed bool, previous []byte) error {
	if existed {
		if previous == nil {
			return errors.New("the previous trust anchor file could not be read before the run")
		}
		return writeWindowsBundleAdminFile(path, previous)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func windowsBundleRollbackDeadlineExpired(ctx context.Context, receipt *enterprisebundle.Receipt, result *enterprisestatus.Result) bool {
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return false
	}
	receipt.WarningCodes = append(receipt.WarningCodes, "rollback_skipped_deadline")
	result.AddWarning("rollback_skipped_deadline", "the ensure deadline expired; bundle rollback was skipped and the installed policy may need recovery on the next ensure")
	return true
}

func windowsBundleEnforces(p enterprisebundle.GatewayPolicy) bool {
	return p.Applied && p.ReloadError == "" && p.Digest != ""
}

func windowsBundleHasCode(messages []enterprisestatus.Message, code string) bool {
	for _, m := range messages {
		if m.Code == code {
			return true
		}
	}
	return false
}

// windowsBundleRollbackTarget is the confirmed bundle whose config a
// rollback installs again.
type windowsBundleRollbackTarget struct {
	store *enterprisebundle.Store
	ref   *enterprisebundle.Ref
	// before is config.generation.json as the run found it, restored the
	// hex SHA-256 of the config the rollback installs. A record that named
	// the bundle for exactly these bytes names it again, also once the
	// bundle's receipt was pruned (GAP-0011).
	before   configwrite.GenerationState
	restored string
}

// writeOptions records the rollback write as the confirmed bundle: its
// principal and bundle fields, so the gateway digests the restored config in
// the bundle's scope and status, verify and ensure find the bundle enforcing.
func (t *windowsBundleRollbackTarget) writeOptions(expectSHA string) (configwrite.Options, error) {
	driver := &enterprisebundle.Driver{Store: t.store}
	raw, ref, err := driver.CurrentConfig()
	if err != nil {
		return configwrite.Options{}, err
	}
	if ref == nil || t.ref == nil || ref.BundleID != t.ref.BundleID || ref.Version != t.ref.Version ||
		ref.ManifestSHA256 != t.ref.ManifestSHA256 || ref.SignerKeyID != t.ref.SignerKeyID ||
		ref.EffectivePolicyDigest != t.ref.EffectivePolicyDigest || configwrite.SHA256Hex(raw) != t.restored {
		return configwrite.Options{}, errors.New("confirmed bundle changed before rollback; run defenseclaw.exe enterprise windows ensure --profile standalone")
	}
	opt, ok, err := driver.ConfigGenerationOptions(raw)
	if err != nil {
		return opt, err
	}
	if !ok {
		return opt, errors.New("cannot prove the confirmed rollback principal; run defenseclaw.exe enterprise windows ensure --profile standalone")
	}
	opt.ExpectSHA256 = expectSHA
	if t.before.BundleID == ref.BundleID && t.before.BundleVersion == ref.Version &&
		t.before.SignerKeyID == opt.Bundle.SignerKeyID && t.before.Actor == opt.Actor {
		opt = configwrite.RestoreOptions(t.before, t.restored, opt)
	}
	return opt, nil
}

// rollbackWindowsBundle installs the last good config again (the current
// bundle config, or the config installed before the run while no bundle is
// current) with a second ensure whose result is not printed: the result of
// this run reports the failed bundle. It returns the digest the gateway then
// enforces and whether the last good config is installed.
func rollbackWindowsBundle(cmd *cobra.Command, opts *windowsEnterpriseLifecycleOptions, run *windowsBundleRun) (string, bool) {
	last, ref, err := run.driver.CurrentConfig()
	if err != nil {
		return "", false
	}
	if ref == nil {
		last = run.previous
	}
	if len(last) == 0 || opts.resolvedInstaller == "" {
		return "", false
	}
	path := filepath.Join(run.layout.LifecycleDir, windowsBundleRollbackName)
	if err := writeWindowsBundleAdminFile(path, last); err != nil {
		return "", false
	}
	defer os.Remove(path)
	rollback := *opts
	rollback.bundle, rollback.bundleRollback, rollback.bundleRollbackTo = nil, true, nil
	if ref != nil {
		rollback.bundleRollbackTo = &windowsBundleRollbackTarget{store: run.driver.Store, ref: ref,
			before: run.previousGeneration, restored: configwrite.SHA256Hex(last)}
	}
	rollback.bundlePath, rollback.trustAnchors, rollback.configPath = "", "", path
	rollback.jsonOutput = true
	out := cmd.OutOrStdout()
	cmd.SetOut(io.Discard)
	rollbackErr := runWindowsEnterpriseStandaloneEnsure(run.ctx, cmd, &rollback, opts.resolvedInstaller)
	cmd.SetOut(out)
	enforcing := ""
	if policy := windowsBundlePolicy(run.ctx); policy != nil {
		enforcing = policy.Digest
	}
	restored := rollbackErr == nil && windowsBundleInstalledSHA(run.layout.ConfigPath) == sha256HexBytes(last)
	if restored && ref != nil {
		// Even byte-identical bundle configs need identity proof. A no-op
		// ensure may not enter the hot-apply adoption check at all.
		identity, err := windowsBundleRollbackIdentity(ref, configwrite.BundleRef{ID: ref.BundleID, Version: ref.Version})
		restored = err == nil && windowsEnterpriseHotConfigAdopted(run.ctx, windowsEnterpriseHotConfigTimeout, identity)
	}
	return enforcing, restored
}

// attachWindowsBundleSummary sets the result v2 bundle block: the receipt
// of this run if it reached staging, else the store summary. A store this account
// cannot read (status as a standard user) adds nothing. It reports whether
// the store has a confirmed current bundle.
func attachWindowsBundleSummary(result *enterprisestatus.Result, store *enterprisebundle.Store, receipt *enterprisebundle.Receipt, sessions *enterprisestatus.SessionRestartStatus) (confirmed bool) {
	if result == nil {
		return false
	}
	attachSessions := func() {
		if sessions == nil {
			status := platformBundleSessionStatus(context.Background())
			sessions = &status
		}
		result.SetBundleSessions(*sessions)
		result.SetBundleReceiptWarnings()
	}
	if store == nil {
		layout, err := windowsBundleLayout()
		if err != nil {
			return false
		}
		store = newWindowsBundleDriver(layout).Store
	}
	if state, err := store.LoadState(); err == nil && state.Current != nil {
		if receipts, err := store.Receipts(); err == nil {
			for _, current := range receipts {
				if current.State == enterprisebundle.StateConfirmed && current.BundleID == state.Current.BundleID && current.Version == state.Current.Version {
					confirmed = true
					if layout, err := windowsBundleLayout(); err == nil {
						if warning := bundleCurrentSignerWarning(newWindowsBundleDriver(layout).AnchorsPath, current.SignerKeyID); warning != nil {
							result.AddWarning(warning.Code, warning.Message)
						}
					}
					break
				}
			}
		}
	}
	if _, refusal, err := store.Latest(); err == nil {
		result.LastRefusal = refusal
	}
	if result.Bundle != nil {
		attachSessions()
		return confirmed
	}
	if receipt != nil && !receipt.IsRefusal() {
		if st, err := store.LoadState(); err == nil {
			result.Bundle = receipt.Status(st.Current)
			attachSessions()
		}
		return confirmed
	}
	if summary, err := store.Summary(); err == nil && summary != nil && summary.BundleID != "" {
		result.Bundle = summary
		attachSessions()
	}
	return confirmed
}

// platformBundleSessionStatus uses the same process inventory and activation
// record as Setup's agent session warning. Bundle commands already require
// an administrator; they need not run as LocalSystem.
func platformBundleSessionStatus(parent context.Context) enterprisestatus.SessionRestartStatus {
	unknown := func(err error) enterprisestatus.SessionRestartStatus {
		return enterprisestatus.SessionRestartStatus{State: "unknown", Entries: []enterprisestatus.SessionEntry{}, Reason: err.Error()}
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	type snapshot struct {
		rows []inventory.AgentProcess
		err  error
	}
	done := make(chan snapshot, 1)
	go func() { rows, err := windowsEnterpriseAgentProcesses(); done <- snapshot{rows, err} }()
	var scanned snapshot
	select {
	case scanned = <-done:
	case <-ctx.Done():
		return unknown(ctx.Err())
	}
	if scanned.err != nil {
		return unknown(scanned.err)
	}
	if len(scanned.rows) > 4096 {
		return unknown(fmt.Errorf("process cap reached"))
	}
	// Only sessions of the connectors the installed config enables can need
	// a restart: an agent DefenseClaw does not manage on this device loads no
	// DefenseClaw hook before or after a bundle (sidecar F04).
	enabled, err := windowsEnterpriseEnrolledConnectors()
	if err != nil {
		return unknown(fmt.Errorf("read the installed config for its enabled connectors: %w", err))
	}
	managedConnector := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		managedConnector[strings.ToLower(name)] = true
	}
	rows := make([]inventory.AgentProcess, 0, len(scanned.rows))
	for _, row := range scanned.rows {
		if managedConnector[strings.ToLower(row.Connector)] {
			rows = append(rows, row)
		}
	}
	scanned.rows = rows
	layout, err := windowsBundleLayout()
	if err != nil {
		return unknown(err)
	}
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		return unknown(err)
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return unknown(err)
	}
	opts := enterprisepolicy.LayoutOptions(layout, programFiles, programData)
	changed := map[string]time.Time{}
	if metadata, installed := windowsEnterpriseActivationMetadata(); installed {
		record, activated := readWindowsEnterpriseActivation(filepath.Join(filepath.Dir(metadata), windowsEnterpriseActivationFileName))
		for _, row := range scanned.rows {
			changed[row.Connector] = activated
			if at, err := time.Parse(time.RFC3339Nano, record.ConnectorActivatedAt[strings.ToLower(row.Connector)]); err == nil && at.After(changed[row.Connector]) {
				changed[row.Connector] = at
			}
		}
	}
	var fallback time.Time
	if raw, err := os.ReadFile(filepath.Join(layout.LifecycleDir, enterprisestatus.PolicyStateFileName)); err == nil {
		var state enterprisestatus.PolicyStateRecord
		if json.Unmarshal(raw, &state) == nil {
			fallback, _ = time.Parse(time.RFC3339Nano, state.AppliedAt)
		}
	}
	processes := make([]enterprisestatus.SessionProcess, 0, len(scanned.rows))
	settingsChecked := map[string]bool{}
	for _, row := range scanned.rows {
		if !settingsChecked[row.Connector] {
			settingsChecked[row.Connector] = true
			target, ok := enterprisepolicy.TargetFor(row.Connector)
			if ok {
				paths, err := target.Paths(opts)
				if err == nil {
					for _, path := range paths {
						if row.Connector == enterprisepolicy.ConnectorClaudeCode && !strings.HasSuffix(path, enterprisepolicy.DefenseClawDropInName) {
							continue
						}
						if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.ModTime().After(changed[row.Connector]) {
							changed[row.Connector] = info.ModTime()
						}
					}
				}
			}
		}
		if changed[row.Connector].IsZero() {
			changed[row.Connector] = fallback
		}
		if changed[row.Connector].IsZero() {
			return unknown(fmt.Errorf("no managed hook activation time for %s", row.Connector))
		}
		if row.User == "" || row.StartedAt.IsZero() {
			return unknown(fmt.Errorf("cannot inspect owner or start time of agent pid %d", row.PID))
		}
		processes = append(processes, enterprisestatus.SessionProcess{PID: row.PID, User: row.User, Agent: row.Connector, StartedAt: row.StartedAt})
	}
	return enterprisestatus.ScanSessions(func() ([]enterprisestatus.SessionProcess, error) { return processes, nil }, changed, true)
}

// readWindowsBundleGatewayPolicy asks the installed CLI for the effective
// policy of the installed config and the digest the gateway reports; nil
// when either cannot be read.
func readWindowsBundleGatewayPolicy(ctx context.Context) *enterprisebundle.GatewayPolicy {
	out, err := windowsEnterprisePolicyDigest(ctx)
	var report policyDigestReport
	if (err != nil && len(out) == 0) || json.Unmarshal(out, &report) != nil {
		return nil
	}
	scratch := enterprisestatus.New("status", managed.ProfileStandalone, "windows", appVersion)
	state := applyEnterprisePolicyReport(scratch, out, false)
	if state == nil {
		return nil
	}
	return &enterprisebundle.GatewayPolicy{EffectiveDigest: state.EffectiveDigest, Digest: state.GatewayReportedDigest,
		Generation: report.GatewayReportedConfigGeneration, BundleID: report.GatewayReportedBundleID, BundleVersion: report.GatewayReportedBundleVersion,
		ReloadError: state.LastReloadError, Applied: state.Applied && !state.ConfigUnrecorded && report.GatewayReportedConfigGeneration == state.ConfigGeneration}
}

// lifecycleGatewayPolicy is the policy block the Windows lifecycle reports:
// the effective policy digest of the installed config and whether the
// running gateway reports it. nil when it cannot be read.
func lifecycleGatewayPolicy(ctx context.Context) *enterprisestatus.PolicyState {
	out, err := windowsEnterprisePolicyDigest(ctx)
	if err != nil && len(out) == 0 {
		return nil
	}
	scratch := enterprisestatus.New("status", managed.ProfileStandalone, "windows", appVersion)
	return applyEnterprisePolicyReport(scratch, out, false)
}

func windowsBundleInstalledSHA(path string) string {
	raw, err := readBoundedConfigFile(path, windowsBundleMaxConfig)
	if err != nil {
		return ""
	}
	return sha256HexBytes(raw)
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeWindowsBundleFile replaces path with data. The caller seals private
// files with AdminFile after the replacement.
func writeWindowsBundleFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp-%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func writeWindowsBundleAdminFile(path string, data []byte) error {
	if err := writeWindowsBundleFile(path, data); err != nil {
		return err
	}
	return windowsBundlePublishPrivateFile(path)
}

// installWindowsBundleAnchors installs the administrator anchor file src
// as <state root>\etc\trust\bundle-anchors.json once it decodes and passes
// the trust check, then checks the installed copy the same way. It returns
// the bytes it wrote, which are the bytes it read and checked once, and
// whether dst was replaced: an error after the replace (its access or its
// check failed) leaves dst changed, which the caller puts back and records
// as a failed change.
func installWindowsBundleAnchors(src, dst string) (installed []byte, replaced bool, err error) {
	// One read: the bytes written are the ones decoded and trust-checked.
	_, raw, err := windowsBundleReadAnchors(src, bundleAnchorTrust)
	if err != nil {
		return nil, false, err
	}
	if err := windowsBundleEnsurePrivateDirectory(filepath.Dir(dst)); err != nil {
		return nil, false, &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
	}
	// writeWindowsBundleFile replaces dst by a rename, its last step.
	if err := writeWindowsBundleFile(dst, raw); err != nil {
		return nil, false, &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
	}
	if err := windowsBundlePublishPrivateFile(dst); err != nil {
		return nil, true, &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
	}
	if _, err := enterprisebundle.LoadAnchors(dst, bundleAnchorTrust); err != nil {
		return nil, true, err
	}
	return raw, true, nil
}

// lockWindowsBundleStore takes the bundle store lock for the run, or
// returns at once when another bundle run holds it (lifecycle_busy: the
// MDM retries on 1618).
func lockWindowsBundleStore(lifecycleDir string) (func(), error) {
	if err := windowsBundleEnsurePrivateDirectory(lifecycleDir); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(filepath.Join(lifecycleDir, windowsBundleLockName))
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	if err := windowsBundlePublishPrivateFile(filepath.Join(lifecycleDir, windowsBundleLockName)); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		_ = windows.CloseHandle(handle)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errWindowsBundleStoreBusy
		}
		return nil, fmt.Errorf("lock the bundle store: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = windows.CloseHandle(handle)
	}, nil
}

// lockWindowsBundleStoreWithin takes the bundle store lock, waiting up to
// wait for another bundle run to release it (`enterprise bundle apply
// --lock-wait`); a wait of 0 returns at once, as lockWindowsBundleStore does.
func lockWindowsBundleStoreWithin(ctx context.Context, lifecycleDir string, wait time.Duration) (func(), error) {
	unlock, err := acquireWindowsLockWithin(ctx, wait, func() (func(), error) { return lockWindowsBundleStore(lifecycleDir) },
		func(err error) bool { return errors.Is(err, errWindowsBundleStoreBusy) })
	if err != nil && wait > 0 && errors.Is(err, errWindowsBundleStoreBusy) {
		return nil, fmt.Errorf("%w (still held after --lock-wait %s)", err, formatWindowsLockWait(wait))
	}
	return unlock, err
}

// writeWindowsBundleMarker publishes the confirmed bundle on the standalone
// marker key for MDM detection (detect.ps1 -RequireBundle): BundleId,
// BundleVersion and BundleState=confirmed, or no bundle values while no
// bundle is current. An unreadable store leaves the values unchanged.
func writeWindowsBundleMarker(marker registry.Key) error {
	layout, err := windowsBundleLayout()
	if err != nil {
		return nil
	}
	st, err := newWindowsBundleDriver(layout).Store.LoadState()
	if err != nil {
		return nil
	}
	if st.Current == nil {
		for _, name := range []string{"BundleId", "BundleVersion", "BundleState"} {
			if err := marker.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
				return fmt.Errorf("remove enterprise marker %s: %w", name, err)
			}
		}
		return nil
	}
	for name, value := range map[string]string{
		"BundleId":      st.Current.BundleID,
		"BundleVersion": strconv.FormatUint(st.Current.Version, 10),
		"BundleState":   enterprisebundle.StateConfirmed,
	} {
		if err := marker.SetStringValue(name, value); err != nil {
			return fmt.Errorf("write enterprise marker %s: %w", name, err)
		}
	}
	return nil
}
