//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// RestoreWindowsClaudeManagedPolicyDrift puts DefenseClaw's own Claude Code
// drop-in (90-defenseclaw.json) back byte for byte when it was edited or
// deleted outside DefenseClaw. The drop-in is DefenseClaw's whole file; its
// ownership record (the protected state sidecar) keeps the digest of the
// bytes DefenseClaw wrote. Every later writer refused the changed file
// ("refusing to overwrite administrator edits"), so the guardian never put
// it back, Claude Code prompts failed closed for every enrolled user, and
// Setup /repair failed 1603 at its lifecycle snapshot (GAP-1108).
//
// It renders the policy for the recorded hook executable and gateway under
// every registered hook contract, with and without the managed-hooks-only
// lock, and writes only the rendering whose digest is the recorded one, so
// it never invents a policy. It reports whether it wrote the file; nothing
// changes when the drop-in matches its record, when no record exists, or
// when no rendering matches (the error says so).
//
// The guardian runs it as LocalSystem. Setup /repair and `enterprise windows
// repair` run it in the administrator's elevated token, before their
// lifecycle snapshot: the drop-in is written with its Administrators owner
// and DACL either way. It refused every token but LocalSystem, so an
// administrator's repair with the guardian stopped kept the changed drop-in
// and failed 1603 (GAP-2336).
func RestoreWindowsClaudeManagedPolicyDrift() (bool, error) {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		if requireWindowsClaudeTeardownAdministrator() != nil {
			return false, err
		}
	}
	if plain, err := windowsClaudeManagedPolicyDirPlain(); err != nil || !plain {
		return false, err
	}
	restored := false
	err := windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
		state, err := snapshotWindowsManagedFileWithLimit(statePath, windowsClaudeManagedStateLimit)
		if err != nil || !state.existed {
			return err
		}
		policy, err := snapshotWindowsManagedFileWithLimit(path, windowsClaudeManagedPolicyLimit)
		if err != nil {
			return err
		}
		if err := windowsManagedPolicyFileTrustCheck(statePath); err != nil {
			return err
		}
		// On standalone the record's own descriptor is judged too, so a
		// record an untrusted account can write or owns is never rendered
		// from, whatever the guardian did before (GAP-0633).
		if err := windowsManagedPolicySelfHealRefusal(statePath, managed.ObjectInstallFile, nil); err != nil {
			return err
		}
		var record windowsClaudeManagedPolicyState
		if err := decodeWindowsClaudeManagedPolicyState(state.data, &record); err != nil {
			return fmt.Errorf("enterprise hooks: read the Claude Code managed policy ownership record: %w", err)
		}
		if policy.existed && windowsManagedPolicyDigest(policy.data) == record.PolicySHA256 {
			return nil
		}
		if record.SchemaVersion != 2 {
			// A standalone computer has no Setup installed: name where it comes
			// from (cowork-1-0-8 GAP-0095). Secure Client keeps its text.
			step := "Setup /ensure"
			if windowsEnterpriseStandaloneProcess() {
				step = "`" + managed.WindowsSetupCommand("/ensure") + "` (" + managed.WindowsSetupSource + ")"
			}
			return errors.New("enterprise hooks: the Claude Code managed policy ownership record is from an earlier release; run " + step)
		}
		if err := requireWindowsClaudeRecordedHookExecutable(record); err != nil {
			return err
		}
		body, err := renderRecordedWindowsClaudeManagedPolicy(record)
		setAside := false
		if err != nil && policy.existed {
			// Rendering reads every managed drop-in, so a changed drop-in that
			// is not JSON, or that turns hooks off, blocks its own rebuild. It
			// is DefenseClaw's own file and is replaced anyway: set it aside
			// and render again, and put it back if that fails too.
			if removeErr := os.Remove(path); removeErr != nil {
				return errors.Join(err, removeErr)
			}
			setAside = true
			body, err = renderRecordedWindowsClaudeManagedPolicy(record)
		}
		rollback := func(cause error) error {
			if !setAside && !policy.existed {
				return cause
			}
			if restoreErr := restoreWindowsManagedFile(policy); restoreErr != nil {
				return errors.Join(cause, fmt.Errorf("enterprise hooks: put back the changed Claude Code drop-in: %w", restoreErr))
			}
			return cause
		}
		if err != nil {
			return rollback(err)
		}
		if err := windowsManagedPolicyWriter(path, body, true); err != nil {
			return rollback(err)
		}
		if err := verifyWindowsClaudeManagedPolicy(path, body); err != nil {
			return rollback(err)
		}
		restored = true
		return nil
	})
	return restored, err
}

// requireWindowsClaudeRecordedHookExecutable refuses, on standalone, an
// ownership record whose hook executable is not this install's own native
// hook, so the restore never renders a drop-in that runs another binary for
// every Claude Code user. The record is trusted only through its descriptor;
// the target install and verify already require the same executable
// (GAP-0633). Secure Client keeps the record as it is.
func requireWindowsClaudeRecordedHookExecutable(record windowsClaudeManagedPolicyState) error {
	if !windowsManagedPolicySelfHealRefusesContentDrift() {
		return nil
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return err
	}
	if !sameWindowsEnterprisePath(record.HookExecutable, hookExecutable) {
		return fmt.Errorf("enterprise hooks: the Claude Code managed policy ownership record names hook executable %s, "+
			"not this install's %s, so the changed drop-in is left as it is; run Setup /ensure", record.HookExecutable, hookExecutable)
	}
	return nil
}

// renderRecordedWindowsClaudeManagedPolicy is the Claude Code policy whose
// digest the ownership record keeps.
func renderRecordedWindowsClaudeManagedPolicy(record windowsClaudeManagedPolicyState) ([]byte, error) {
	if !filepath.IsAbs(record.HookExecutable) || filepath.Clean(record.HookExecutable) != record.HookExecutable {
		return nil, errors.New("enterprise hooks: the Claude Code managed policy ownership record names no canonical hook executable")
	}
	for _, contract := range windowsClaudeRecordedPolicyContracts() {
		for _, lock := range []bool{true, false} {
			body, err := renderWindowsClaudeRecordedPolicy(record, contract, lock)
			if err == nil && windowsManagedPolicyDigest(body) == record.PolicySHA256 {
				return body, nil
			}
		}
	}
	return nil, fmt.Errorf("enterprise hooks: no Claude Code policy this release renders for %s has the digest its ownership record keeps, so the changed drop-in is left as it is", record.HookExecutable)
}

// windowsClaudeRecordedPolicyContracts is every hook contract a recorded
// drop-in may have been rendered under: none, then each known one.
func windowsClaudeRecordedPolicyContracts() []string {
	contracts := []string{""}
	for _, contract := range connector.KnownHookContracts("claudecode") {
		contracts = append(contracts, contract.ContractID)
	}
	return contracts
}

// renderWindowsClaudeRecordedPolicy renders the drop-in for the record's hook
// executable and gateway under contract, with or without the
// managed-hooks-only lock.
func renderWindowsClaudeRecordedPolicy(record windowsClaudeManagedPolicyState, contract string, lock bool) ([]byte, error) {
	return connector.NewClaudeCodeConnector().ManagedHookPolicy(connector.SetupOpts{
		APIAddr:                     record.GatewayAddr,
		HookFailMode:                "closed",
		ManagedEnterprise:           true,
		HookExecutable:              record.HookExecutable,
		HookContractID:              contract,
		ClaudeAllowManagedHooksOnly: lock,
	})
}

// ApplyWindowsClaudeManagedHooksOnlyLock writes the configured
// managed_hooks_only setting into DefenseClaw's own Claude Code drop-in
// (90-defenseclaw.json) and reports whether it wrote it. The lock is machine
// policy only: no file in an account's profile carries it. Only a target's
// own install rewrote the drop-in, and the guardian installs a target only in
// its account's Windows session, so a config-only Setup /ensure that changed
// managed_hooks_only while an enrolled account was signed out failed every
// such target's verification, could not repair it, and failed 1603 with a
// rollback (cowork-1-0-8 GAP-0064).
//
// It replaces the drop-in only when it is, byte for byte, the rendering its
// ownership record keeps with the other lock (the same hook executable,
// gateway and contract), and keeps the enrolled SIDs. Any other drop-in is
// left alone: an edit outside DefenseClaw stays a verification failure, and
// RestoreWindowsClaudeManagedPolicyDrift puts DefenseClaw's own bytes back.
// Standalone only: a Secure Client drop-in never carries the lock.
func ApplyWindowsClaudeManagedHooksOnlyLock() (bool, error) {
	if !windowsEnterpriseStandaloneProcess() {
		return false, nil
	}
	// LocalSystem (the guardian) or an elevated administrator, as for
	// RestoreWindowsClaudeManagedPolicyDrift.
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		if requireWindowsClaudeTeardownAdministrator() != nil {
			return false, err
		}
	}
	if plain, err := windowsClaudeManagedPolicyDirPlain(); err != nil || !plain {
		return false, err
	}
	want := windowsClaudeManagedHooksOnlyEnforced()
	written := false
	err := windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
		state, err := snapshotWindowsManagedFileWithLimit(statePath, windowsClaudeManagedStateLimit)
		if err != nil {
			return err
		}
		policy, err := snapshotWindowsManagedFileWithLimit(path, windowsClaudeManagedPolicyLimit)
		if err != nil || !policy.existed || !state.existed {
			return err
		}
		if windowsClaudeManagedPolicyHasLock(policy.data) == want {
			return nil
		}
		record, err := validateExistingWindowsManagedPolicyOwnership(policy, state)
		if err != nil || record.SchemaVersion != 2 {
			// A changed drop-in or an earlier release's record is not a
			// setting change: the target verification reports it.
			return nil
		}
		var body []byte
		for _, contract := range windowsClaudeRecordedPolicyContracts() {
			current, renderErr := renderWindowsClaudeRecordedPolicy(record, contract, !want)
			if renderErr != nil || !bytes.Equal(current, policy.data) {
				continue
			}
			if body, err = renderWindowsClaudeRecordedPolicy(record, contract, want); err != nil {
				return err
			}
			break
		}
		if body == nil {
			return nil
		}
		record.PolicySHA256 = windowsManagedPolicyDigest(body)
		stateBody, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			return err
		}
		stateBody = append(stateBody, '\n')
		rollback := func(cause error) error {
			for _, snapshot := range []windowsManagedFileSnapshot{policy, state} {
				if restoreErr := restoreWindowsManagedFile(snapshot); restoreErr != nil {
					cause = errors.Join(cause, fmt.Errorf("enterprise hooks: put back the Claude Code drop-in: %w", restoreErr))
				}
			}
			return cause
		}
		if err := windowsManagedPolicyWriter(path, body, true); err != nil {
			return rollback(err)
		}
		if err := windowsManagedPolicyWriter(statePath, stateBody, true); err != nil {
			return rollback(err)
		}
		if err := verifyWindowsClaudeManagedPolicy(path, body); err != nil {
			return rollback(err)
		}
		written = true
		return nil
	})
	return written, err
}

// WindowsClaudeManagedPolicyDrift names DefenseClaw's own Claude Code drop-in
// when it no longer has the digest its ownership record keeps: an
// administrator or a tool edited or deleted it, so some DefenseClaw hook
// entries may be missing until the guardian, repair or reconcile puts it
// back. It only reads. It returns "" when there is no trusted record, when
// the drop-in matches it, or when the files cannot be read; removed says the
// drop-in is gone.
func WindowsClaudeManagedPolicyDrift() (path string, removed bool) {
	policyPath, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return "", false
	}
	statePath := filepath.Join(filepath.Dir(policyPath), windowsClaudeManagedStateFile)
	state, err := snapshotWindowsManagedFileWithLimit(statePath, windowsClaudeManagedStateLimit)
	if err != nil || !state.existed || windowsManagedPolicyFileTrustCheck(statePath) != nil {
		return "", false
	}
	var record windowsClaudeManagedPolicyState
	if decodeWindowsClaudeManagedPolicyState(state.data, &record) != nil || record.PolicySHA256 == "" {
		return "", false
	}
	policy, err := snapshotWindowsManagedFileWithLimit(policyPath, windowsClaudeManagedPolicyLimit)
	if err != nil {
		return "", false
	}
	if policy.existed && windowsManagedPolicyDigest(policy.data) == record.PolicySHA256 {
		return "", false
	}
	return policyPath, !policy.existed
}
