// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// VerifyWindowsClaudeManagedPolicyIdentity is a read-only proof that the
// active protected Claude policy belongs to the current gateway deployment.
// Target-set equality is checked separately by the caller.
func VerifyWindowsClaudeManagedPolicyIdentity(
	hookExecutable, gatewayAddr, gatewayServiceName string,
) error {
	if !filepath.IsAbs(hookExecutable) || filepath.Clean(hookExecutable) != hookExecutable {
		return errors.New("enterprise hooks: Claude machine-policy hook executable is noncanonical")
	}
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: Claude machine-policy hook executable is untrusted: %w", err)
	}
	gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(gatewayAddr)
	if err != nil {
		return err
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(gatewayServiceName); err != nil {
		return err
	}
	setup := withWindowsClaudeManagedHooksOnly(connector.SetupOpts{
		APIAddr:           gatewayAddr,
		HookFailMode:      "closed",
		ManagedEnterprise: true,
		HookExecutable:    hookExecutable,
	})
	provider := connector.NewClaudeCodeConnector()
	return windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		policy, err := snapshotWindowsManagedFileWithLimit(path, windowsClaudeManagedPolicyLimit)
		if err != nil {
			return err
		}
		state, err := snapshotWindowsManagedFileWithLimit(
			filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile),
			windowsClaudeManagedStateLimit,
		)
		if err != nil {
			return err
		}
		parsed, err := validateExistingWindowsManagedPolicyOwnership(policy, state)
		if err != nil {
			return err
		}
		if !policy.existed {
			return errors.New("enterprise hooks: Claude managed policy is absent")
		}
		if parsed.SchemaVersion != 2 ||
			!sameWindowsEnterprisePath(parsed.HookExecutable, hookExecutable) ||
			parsed.GatewayAddr != gatewayAddr ||
			parsed.GatewayServiceName != gatewayServiceName {
			return errors.New("enterprise hooks: Claude machine policy belongs to another protected gateway deployment")
		}
		if err := provider.VerifyManagedHookPolicy(policy.data, setup); err != nil {
			if !windowsStandaloneProfilePinned() {
				return fmt.Errorf("enterprise hooks: verify current Claude managed policy identity: %w", err)
			}
			// The policy was rendered for the enrolled Claude version's hook
			// contract (for example with DirectoryAdded from 2.1.219), which
			// this version-less setup cannot know. It is still this
			// deployment's policy if it is byte-for-byte the rendering of
			// one registered contract for the same executable and gateway,
			// with or without the managed-hooks-only lock: a policy an older
			// release published without the lock still belongs to this
			// deployment, and the guardian's canonical check re-renders it.
			if !claudeManagedPolicyMatchesKnownContract(provider, policy.data, setup) {
				return fmt.Errorf("enterprise hooks: verify current Claude managed policy identity: %w", err)
			}
		}
		return nil
	})
}

func claudeManagedPolicyMatchesKnownContract(
	provider *connector.ClaudeCodeConnector,
	policy []byte,
	setup connector.SetupOpts,
) bool {
	for _, contract := range connector.KnownHookContracts("claudecode") {
		for _, lock := range []bool{setup.ClaudeAllowManagedHooksOnly, !setup.ClaudeAllowManagedHooksOnly} {
			pinned := setup
			pinned.HookContractID = contract.ContractID
			pinned.ClaudeAllowManagedHooksOnly = lock
			if provider.VerifyManagedHookPolicy(policy, pinned) == nil {
				return true
			}
		}
	}
	return false
}

// windowsStandaloneProfilePinned reports whether this service runs under the
// standalone enterprise profile pin.
func windowsStandaloneProfilePinned() bool {
	return managed.IsStandaloneProfile(os.Getenv(managed.EnterpriseProfileEnv))
}

// VerifyWindowsCursorManagedPolicyIdentity is the equivalent read-only proof
// for the singleton Cursor adapter/state transaction.
func VerifyWindowsCursorManagedPolicyIdentity(
	hookExecutable, gatewayAddr, gatewayServiceName string,
) error {
	if !filepath.IsAbs(hookExecutable) || filepath.Clean(hookExecutable) != hookExecutable {
		return errors.New("enterprise hooks: Cursor machine-policy hook executable is noncanonical")
	}
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor machine-policy hook executable is untrusted: %w", err)
	}
	gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(gatewayAddr)
	if err != nil {
		return err
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(gatewayServiceName); err != nil {
		return err
	}
	return withWindowsCursorManagedTransaction(func() error {
		artifacts, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		artifacts, err = validateWindowsCursorManagedArtifacts(artifacts)
		if err != nil {
			return err
		}
		if !artifacts.active {
			return errors.New("enterprise hooks: Cursor managed policy is absent")
		}
		state := artifacts.parsed
		if !sameWindowsEnterprisePath(state.HookExecutable, hookExecutable) ||
			state.GatewayAddr != gatewayAddr ||
			state.GatewayServiceName != gatewayServiceName {
			return errors.New("enterprise hooks: Cursor machine policy belongs to another protected gateway deployment")
		}
		return nil
	})
}
