// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

var (
	windowsManagedRuntimeGenerationPrepare  = PrepareWindowsManagedRuntimeGeneration
	windowsManagedRuntimeGenerationCommit   = CommitWindowsManagedRuntimeGeneration
	windowsManagedRuntimeGenerationDiscard  = DiscardWindowsManagedRuntimeGenerationPublication
	windowsManagedRuntimeGenerationResolve  = ResolveWindowsManagedRuntimeGeneration
	windowsManagedRuntimeGenerationVerify   = VerifyWindowsManagedRuntimeGeneration
	windowsManagedRuntimeGenerationFinalize = func(commit WindowsManagedRuntimeSelectorCommit) error {
		return commit.Finalize()
	}
)

func prepareWindowsManagedRuntimeGenerationForInstall(
	connectorName string,
	targetSID *windows.SID,
	dataDir,
	hookExecutable,
	gatewayAddr,
	scopedToken,
	hookContractID,
	hookContractLockUpdatedAt,
	hookContractEntryUpdatedAt string,
	failMode ...string,
) (WindowsManagedRuntimeGenerationPublication, error) {
	if targetSID == nil {
		return WindowsManagedRuntimeGenerationPublication{}, errors.New(
			"enterprise hooks: managed runtime generation target SID is unavailable",
		)
	}
	serviceName := strings.TrimSpace(os.Getenv(connector.WindowsGatewayServiceNameEnv))
	if err := connector.ValidateWindowsManagedGatewayServiceName(serviceName); err != nil {
		return WindowsManagedRuntimeGenerationPublication{}, fmt.Errorf(
			"enterprise hooks: managed runtime generation gateway service is invalid: %w",
			err,
		)
	}
	return windowsManagedRuntimeGenerationPrepare(
		WindowsManagedRuntimeGenerationDesired{
			Connector:                  strings.ToLower(strings.TrimSpace(connectorName)),
			TargetSID:                  targetSID.String(),
			DataDir:                    dataDir,
			HookExecutable:             hookExecutable,
			GatewayAddr:                gatewayAddr,
			GatewayServiceName:         serviceName,
			FailMode:                   windowsManagedGenerationFailMode(failMode),
			ScopedToken:                scopedToken,
			HookContractID:             hookContractID,
			HookContractLockUpdatedAt:  hookContractLockUpdatedAt,
			HookContractEntryUpdatedAt: hookContractEntryUpdatedAt,
		},
	)
}

func rollbackWindowsManagedRuntimeGeneration(
	commit WindowsManagedRuntimeSelectorCommit,
	publication WindowsManagedRuntimeGenerationPublication,
) error {
	// Restore the selector first. Discard then proves the new immutable bundle
	// is no longer selected before deleting it; a concurrent same-SID update
	// makes both operations fail closed instead of deleting another generation.
	return errors.Join(
		commit.Rollback(),
		windowsManagedRuntimeGenerationDiscard(publication),
	)
}

// retireWindowsManagedRuntimePreviousGeneration deletes the bundle a
// successful install just replaced, so rotations of the token, gateway, fail
// mode or contract stop piling up stale bundles toward the collection cap.
// It runs only when the embedding process says no lifecycle transaction could
// still roll back to that bundle, and it is best effort: a bundle that cannot
// be retired is logged and left for generation collection.
func retireWindowsManagedRuntimePreviousGeneration(commit WindowsManagedRuntimeSelectorCommit) {
	allowed := WindowsManagedRuntimeRetirePreviousGenerationAllowed
	if allowed == nil || !commit.Changed() || !allowed() {
		return
	}
	if err := windowsManagedRuntimeGenerationFinalize(commit); err != nil {
		managed.EmitResilienceEvent(managed.MarkerSkip, map[string]string{
			"connector": commit.connector,
			"sid":       commit.targetSID,
			"reason":    "runtime_generation_retire_skipped: " + err.Error(),
		})
	}
}

func discardWindowsManagedRuntimeGeneration(
	publication WindowsManagedRuntimeGenerationPublication,
) error {
	return windowsManagedRuntimeGenerationDiscard(publication)
}

func verifyWindowsManagedRuntimeGenerationForInstall(
	connectorName string,
	targetSID *windows.SID,
	dataDir,
	hookExecutable,
	gatewayAddr,
	scopedToken,
	hookContractID,
	hookContractLockUpdatedAt,
	hookContractEntryUpdatedAt string,
	failMode ...string,
) error {
	if targetSID == nil {
		return errors.New("enterprise hooks: managed runtime generation target SID is unavailable")
	}
	serviceName := strings.TrimSpace(os.Getenv(connector.WindowsGatewayServiceNameEnv))
	if err := connector.ValidateWindowsManagedGatewayServiceName(serviceName); err != nil {
		return err
	}
	return windowsManagedRuntimeGenerationVerify(
		WindowsManagedRuntimeGenerationDesired{
			Connector:                  strings.ToLower(strings.TrimSpace(connectorName)),
			TargetSID:                  targetSID.String(),
			DataDir:                    dataDir,
			HookExecutable:             hookExecutable,
			GatewayAddr:                gatewayAddr,
			GatewayServiceName:         serviceName,
			FailMode:                   windowsManagedGenerationFailMode(failMode),
			ScopedToken:                scopedToken,
			HookContractID:             hookContractID,
			HookContractLockUpdatedAt:  hookContractLockUpdatedAt,
			HookContractEntryUpdatedAt: hookContractEntryUpdatedAt,
		},
	)
}

func windowsManagedGenerationFailMode(modes []string) string {
	if len(modes) == 0 {
		return "open"
	}
	return canonicalHookFailMode(modes[0])
}
