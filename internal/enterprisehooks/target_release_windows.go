// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// WindowsProtectedTargetHasClosedMachineRegistration proves that a signed-out
// target still has an active machine hook and that its selected runtime is
// closed. A protected lock by itself cannot establish either fact.
func WindowsProtectedTargetHasClosedMachineRegistration(opts InstallOptions) (bool, error) {
	return windowsProtectedTargetMachineRegistration(opts, true)
}

// WindowsProtectedTargetHasMachineRegistration is
// WindowsProtectedTargetHasClosedMachineRegistration for a deployment whose
// administrator chose hook fail mode open for the connector (the choice is
// honoured): the machine hook still registers the target's SID and the
// selected runtime, if any, is the account's own valid one, but neither the
// configuration nor the runtime has to be closed. It proves the registration,
// never that the hook fails closed (GAP-0980).
func WindowsProtectedTargetHasMachineRegistration(opts InstallOptions) (bool, error) {
	return windowsProtectedTargetMachineRegistration(opts, false)
}

func windowsProtectedTargetMachineRegistration(opts InstallOptions, requireClosed bool) (bool, error) {
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name != "claudecode" && name != "codex" {
		return false, nil
	}
	if requireClosed && canonicalHookFailModeFor(opts.HookFailMode, false) != "closed" {
		return false, nil
	}
	lock, err := windowsProtectedTargetLock(opts)
	if err != nil || lock.Connector != name ||
		(requireClosed && canonicalHookFailModeFor(lock.HookFailMode, false) != "closed") {
		return false, err
	}
	home, sid, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return false, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return false, err
	}
	hook, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return false, err
	}
	if err := windowsEnterpriseHookTrustCheck(hook); err != nil {
		return false, err
	}
	registered, err := windowsMachinePolicyRegisteredSIDs(name, hook)
	if err != nil || !registered[strings.ToUpper(sid.String())] {
		return false, err
	}
	// An absent administrator-owned selector makes the registered hook fail
	// closed. If it selects this SID, prove the selected, digest-bound bundle
	// is closed; an unreadable or changing selection is not an admission.
	selector, first, exists, err := readWindowsManagedRuntimeSelector(name, true)
	if err != nil {
		return false, err
	}
	if !exists {
		return true, nil
	}
	entry, selected := windowsManagedRuntimeSelectorTargetForSID(selector, sid.String())
	if !selected {
		return true, nil
	}
	if err := validateWindowsManagedRuntimeSelectorTargetAgainstResolve(entry, WindowsManagedRuntimeGenerationResolveOptions{
		Connector: name, TargetSID: sid.String(), DataDir: dataDir, HookExecutable: hook, MachinePolicyRegistered: true,
	}); err != nil {
		return false, err
	}
	bundle, _, _, err := loadWindowsManagedRuntimeBundle(entry, sid)
	if err != nil {
		return false, err
	}
	if err := validateWindowsManagedRuntimeBundleAgainstSelector(bundle, entry); err != nil {
		return false, err
	}
	_, second, stillExists, err := readWindowsManagedRuntimeSelector(name, false)
	if err != nil || !stillExists || !bytes.Equal(first, second) {
		return false, err
	}
	return !requireClosed || bundle.FailMode == "closed", nil
}

// WindowsProtectedTargetFromOtherRelease reads, without writing, the
// protected hook-contract lock entry of one managed target and reports the
// DefenseClaw release that wrote it when that is another release than this
// binary. The guardian asks only after the target failed verification while
// its account is signed out: an upgrade renders new hooks that only the
// account's own Windows session can install, so the target waits for that
// account's next sign-in instead of failing the whole upgrade (GAP-0644).
// A lock that cannot be read, or one this release wrote, is not from
// another release; such a failure stays a failure. Both profiles: a Secure
// Client upgrade with a signed-out enrolled account failed the same way.
//
// The lock is in the account's own DefenseClaw folder, which the account
// owns and can write. The guardian counts its release only for a target this
// release has not yet protected (internal/cli
// enterpriseHookTargetReleaseNotProtectedHere, GAP-1762): an account this
// release already protected that edited defenseclaw_version back to the
// release it replaced turned its own tampering into a sign-in wait. On the
// standalone profile the release also has to be one the administrator-only
// machine release history proves this computer ran (windowsMachineRanRelease,
// GAP-1537, GAP-0644): the Hermes earlier-matrix, prior-render and open-mode
// waits there depend on which release it was. A release the history does not
// name, and any error reading the history, is not another release. Secure
// Client deployment records keep their historical field set and name no
// release, so Setup records no history there; its one wait needs only that
// the lock is another release's, and an account forging one earlier release
// for another gains nothing.
func WindowsProtectedTargetFromOtherRelease(opts InstallOptions) (string, bool, error) {
	lock, err := windowsProtectedTargetLock(opts)
	if err != nil {
		return "", false, err
	}
	written := strings.TrimSpace(lock.DefenseClawVersion)
	if written == "" || written == strings.TrimSpace(version.Current().BinaryVersion) {
		return "", false, nil
	}
	if !windowsEnterpriseStandaloneProcess() {
		return written, true, nil
	}
	ran, err := windowsMachineRanRelease(written)
	if err != nil || !ran {
		return "", false, err
	}
	return written, true, nil
}

// WindowsProtectedTargetRetireRender reads, without writing, the protected
// hook-contract lock entry and the protected runtime selector of one managed
// target, and reports this release as the lock's writer when this release
// wrote the lock while the selector records, for the target SID, an earlier
// trusted hook image of this install (windowsPriorReleaseTargetHookImage).
// That is the render of a hook-image retire: this release rewrote the
// account's records for the transition image bin\defenseclaw-hook.exe before
// the administrator went back to 1.0.9, which accepts that render and leaves
// it and its lock as they are. After the upgrade back the lock names this
// release, so WindowsProtectedTargetFromOtherRelease says no, and an account
// with no active session failed instead of waiting for its sign-in (GAP-1096,
// cert replay on IB4). The guardian asks it only for its read-only proof that
// accepts the earlier release's render, never for another sign-in wait: the
// Hermes earlier-matrix wait trusts the account's own config and Secure Client
// trusts the lock alone, so a retire render must not open them. Any other lock,
// and any error reading the selector, reads as no.
func WindowsProtectedTargetRetireRender(opts InstallOptions) (string, bool, error) {
	lock, err := windowsProtectedTargetLock(opts)
	if err != nil {
		return "", false, err
	}
	written := strings.TrimSpace(lock.DefenseClawVersion)
	if written == "" || written != strings.TrimSpace(version.Current().BinaryVersion) ||
		!windowsProtectedTargetRecordsEarlierHookImage(opts) {
		return "", false, nil
	}
	return written, true, nil
}

// windowsProtectedTargetRecordsEarlierHookImage reports that the protected
// runtime selector records, for the target SID, an earlier trusted hook image
// of this install than the one this release names
// (windowsPriorReleaseTargetHookImage). Any error reads as no.
func windowsProtectedTargetRecordsEarlierHookImage(opts InstallOptions) bool {
	_, sid, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return false
	}
	current, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return false
	}
	prior := opts
	prior.AcceptPriorReleaseRender = true
	return windowsPriorReleaseTargetHookImage(prior, opts.ConnectorName, sid, current) != current
}

// WindowsProtectedTargetRunsEarlierHookMatrix reads, without writing, one
// managed target's agent config and reports that it holds the hook matrix an
// earlier release registered, which differs from this release's only by the
// fail_closed setting Setup added since
// (connector.HookRegistrationLacksOnlyFailClosed). The guardian asks only for
// a target another release protected that fails verification while its
// account has no active session: its earlier hooks still guard the account
// until the guardian upgrades them in that session (rel-1-0-5 GAP-2463).
// The account can write that config, so the guardian asks only when the
// release WindowsProtectedTargetFromOtherRelease proved this computer ran is
// one from before fail_closed (connector.HermesReleaseRegisteredWithoutFailClosed,
// GAP-1537).
func WindowsProtectedTargetRunsEarlierHookMatrix(opts InstallOptions) (bool, error) {
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return false, err
	}
	var earlier bool
	err = connector.WithUserHomeDir(target.home, func() error {
		var checkErr error
		earlier, checkErr = connector.HookRegistrationLacksOnlyFailClosed(target.conn, target.setup)
		return checkErr
	})
	return earlier, err
}

// WindowsProtectedTargetHookFailModeChange reads, without writing, one
// managed target's protected hook-contract lock entry and returns the hook
// fail mode it records and the one opts asks for, both canonical; locked is
// "" without an entry for the target's connector. An administrator who
// changes the hook fail mode makes every enrolled target fail verification,
// and the guardian asks only after one failed while its account has no
// active session (rel-1-0-4 GAP-0585): a change to open waits for the next
// sign-in, its hooks still failing closed, and a change to closed is
// rendered now, under a disconnected session or an S4U logon.
func WindowsProtectedTargetHookFailModeChange(opts InstallOptions) (locked, wanted string, err error) {
	lock, err := windowsProtectedTargetLock(opts)
	if err != nil {
		return "", "", err
	}
	wanted = canonicalHookFailMode(opts.HookFailMode)
	if lock.Connector == "" {
		return "", wanted, nil
	}
	return canonicalHookFailMode(lock.HookFailMode), wanted, nil
}

// windowsProtectedTargetLock reads, without writing, the protected
// hook-contract lock entry of one managed target; an entry for another
// connector reads as none.
func windowsProtectedTargetLock(opts InstallOptions) (connector.HookContractLockEntry, error) {
	home, _, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return connector.HookContractLockEntry{}, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return connector.HookContractLockEntry{}, err
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	lock, err := connector.LoadHookContractLockEntryForMode(dataDir, name, true)
	if err != nil || lock.Connector != name {
		return connector.HookContractLockEntry{}, err
	}
	return lock, nil
}

// WindowsSecureClientProfileProcess reports whether this guardian serves the
// Secure Client profile rather than the standalone one.
func WindowsSecureClientProfileProcess() bool {
	return !windowsEnterpriseStandaloneProcess()
}

// IsWindowsEnterpriseNotLocalSystem reports the refusal of a session or
// mutation check run outside LocalSystem, such as Setup's own verify as the
// elevated administrator, which cannot query another account's session.
func IsWindowsEnterpriseNotLocalSystem(err error) bool {
	return errors.Is(err, errWindowsEnterpriseNotLocalSystem)
}
