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
	"golang.org/x/sys/windows"
)

var (
	windowsManagedRuntimeGenerationPrepare = PrepareWindowsManagedRuntimeGeneration
	windowsManagedRuntimeGenerationCommit  = CommitWindowsManagedRuntimeGeneration
	windowsManagedRuntimeGenerationDiscard = DiscardWindowsManagedRuntimeGenerationPublication
	windowsManagedRuntimeGenerationResolve = ResolveWindowsManagedRuntimeGeneration
	windowsManagedRuntimeGenerationVerify  = VerifyWindowsManagedRuntimeGeneration
	windowsManagedRuntimeGenerationRemove  = RemoveWindowsManagedRuntimeGenerationEnrollment
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
			ScopedToken:                scopedToken,
			HookContractID:             hookContractID,
			HookContractLockUpdatedAt:  hookContractLockUpdatedAt,
			HookContractEntryUpdatedAt: hookContractEntryUpdatedAt,
		},
	)
}
