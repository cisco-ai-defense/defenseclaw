// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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

		SecureClientHookDelivery: secureClientHookDelivery(),
	})
	provider := windowsClaudeManagedPolicyIdentityProvider()
	if kept, keptErr := windowsClaudeManagedPolicyLinkKept(); keptErr != nil || kept {
		if keptErr != nil {
			return keptErr
		}
		return errors.New("enterprise hooks: Claude managed policy is absent: a link sits at the managed-settings folder")
	}
	// The lock gives one consistent read of the drop-in and its ownership
	// record; the drop-in bytes read under it are checked after it is
	// released. Checking them renders the policy up to once per contract,
	// lock and guard form, each rendering checking the hook executables:
	// 5 s under the lock on a managed host, every deferred-staging pass,
	// which Setup /uninstall's 10 s lock wait could lose (rel-1-0-10
	// GAP-1713).
	var published []byte
	err = withWindowsClaudeManagedPolicyTeardownTransaction(func() error {
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
		// A policy an older launch image of this install wrote belongs to
		// this deployment (GAP-0751); it is checked as rendered for the
		// executable it names.
		if parsed.SchemaVersion != 2 ||
			!sameWindowsManagedHookImage(parsed.HookExecutable, hookExecutable) ||
			parsed.GatewayAddr != gatewayAddr ||
			parsed.GatewayServiceName != gatewayServiceName {
			return errors.New("enterprise hooks: Claude machine policy belongs to another protected gateway deployment")
		}
		// The guard texts follow the recorded executable, not the caller's:
		// during a retire the caller names the transition image while the
		// drop-in can still name a launch folder (rel-1-0-10 GAP-1567).
		setup.HookExecutable = parsed.HookExecutable
		published = policy.data
		return nil
	})
	if err != nil {
		return err
	}
	setup = withWindowsClaudeManagedHooksOnly(setup)
	if err := provider.VerifyManagedHookPolicy(published, setup); err != nil {
		// The policy was rendered for the enrolled Claude version's hook
		// contract (for example with DirectoryAdded from 2.1.219), which
		// this version-less setup cannot know, under either profile. It
		// is still this deployment's policy if it is byte-for-byte the
		// rendering of one registered contract for the same executable
		// and gateway, with or without the managed-hooks-only lock: a
		// policy an older release published without the lock still
		// belongs to this deployment, and the guardian's canonical check
		// re-renders it. So is the drop-in in the other guard texts (the
		// 1.0.9 form a retire writes, or the current one), GAP-1567.
		if !claudeManagedPolicyMatchesKnownContract(provider, published, setup) {
			return fmt.Errorf("enterprise hooks: verify current Claude managed policy identity: %w", err)
		}
	}
	return nil
}

// windowsClaudeManagedPolicyIdentityProvider is the Claude provider the
// identity proof checks the published drop-in with. Tests replace it.
var windowsClaudeManagedPolicyIdentityProvider = func() connector.ManagedHookPolicyProvider {
	return connector.NewClaudeCodeConnector()
}

func claudeManagedPolicyMatchesKnownContract(
	provider connector.ManagedHookPolicyProvider,
	policy []byte,
	setup connector.SetupOpts,
) bool {
	for _, contractID := range windowsClaudeRecordedPolicyContracts() {
		for _, lock := range []bool{setup.ClaudeAllowManagedHooksOnly, !setup.ClaudeAllowManagedHooksOnly} {
			for _, texts109 := range []bool{setup.ClaudeManagedGuardTexts109, !setup.ClaudeManagedGuardTexts109} {
				pinned := setup
				pinned.HookContractID = contractID
				pinned.ClaudeAllowManagedHooksOnly = lock
				pinned.ClaudeManagedGuardTexts109 = texts109
				if provider.VerifyManagedHookPolicy(policy, pinned) == nil {
					return true
				}
			}
			// An authenticated standalone policy from the earlier direct
			// delivery form remains this deployment's policy during upgrade.
			if !setup.SecureClientHookDelivery {
				pinned := setup
				pinned.HookContractID = contractID
				pinned.ClaudeAllowManagedHooksOnly = lock
				pinned.SecureClientHookDelivery = true
				if provider.VerifyManagedHookPolicy(policy, pinned) == nil {
					return true
				}
			}
		}
	}
	return false
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
	return withWindowsCursorManagedTeardownTransaction(func() error {
		artifacts, err := snapshotWindowsCursorManagedArtifacts()
		if err != nil {
			return err
		}
		artifacts, err = validateWindowsCursorManagedArtifactsForLockedRead(artifacts)
		if err != nil {
			return err
		}
		if !artifacts.active {
			return errors.New("enterprise hooks: Cursor managed policy is absent")
		}
		state := artifacts.parsed
		if !sameWindowsManagedHookImage(state.HookExecutable, hookExecutable) ||
			state.GatewayAddr != gatewayAddr ||
			state.GatewayServiceName != gatewayServiceName {
			return errors.New("enterprise hooks: Cursor machine policy belongs to another protected gateway deployment")
		}
		return nil
	})
}
