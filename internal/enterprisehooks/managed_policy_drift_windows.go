//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
func RestoreWindowsClaudeManagedPolicyDrift() (bool, error) {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
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
		var record windowsClaudeManagedPolicyState
		if err := decodeWindowsClaudeManagedPolicyState(state.data, &record); err != nil {
			return fmt.Errorf("enterprise hooks: read the Claude Code managed policy ownership record: %w", err)
		}
		if policy.existed && windowsManagedPolicyDigest(policy.data) == record.PolicySHA256 {
			return nil
		}
		if record.SchemaVersion != 2 {
			return errors.New("enterprise hooks: the Claude Code managed policy ownership record is from an earlier release; run Setup /ensure")
		}
		body, err := renderRecordedWindowsClaudeManagedPolicy(record)
		if err != nil {
			return err
		}
		if err := windowsManagedPolicyWriter(path, body, true); err != nil {
			return err
		}
		if err := verifyWindowsClaudeManagedPolicy(path, body); err != nil {
			return err
		}
		restored = true
		return nil
	})
	return restored, err
}

// renderRecordedWindowsClaudeManagedPolicy is the Claude Code policy whose
// digest the ownership record keeps.
func renderRecordedWindowsClaudeManagedPolicy(record windowsClaudeManagedPolicyState) ([]byte, error) {
	if !filepath.IsAbs(record.HookExecutable) || filepath.Clean(record.HookExecutable) != record.HookExecutable {
		return nil, errors.New("enterprise hooks: the Claude Code managed policy ownership record names no canonical hook executable")
	}
	provider := connector.NewClaudeCodeConnector()
	contracts := []string{""}
	for _, contract := range connector.KnownHookContracts("claudecode") {
		contracts = append(contracts, contract.ContractID)
	}
	for _, contract := range contracts {
		for _, lock := range []bool{true, false} {
			body, err := provider.ManagedHookPolicy(connector.SetupOpts{
				APIAddr:                     record.GatewayAddr,
				HookFailMode:                "closed",
				ManagedEnterprise:           true,
				HookExecutable:              record.HookExecutable,
				HookContractID:              contract,
				ClaudeAllowManagedHooksOnly: lock,
			})
			if err == nil && windowsManagedPolicyDigest(body) == record.PolicySHA256 {
				return body, nil
			}
		}
	}
	return nil, fmt.Errorf("enterprise hooks: no Claude Code policy this release renders for %s has the digest its ownership record keeps, so the changed drop-in is left as it is", record.HookExecutable)
}
