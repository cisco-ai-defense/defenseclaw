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
	setup := connector.SetupOpts{
		APIAddr:           gatewayAddr,
		HookFailMode:      "closed",
		ManagedEnterprise: true,
		HookExecutable:    hookExecutable,
	}
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
			return fmt.Errorf("enterprise hooks: verify current Claude managed policy identity: %w", err)
		}
		return nil
	})
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
