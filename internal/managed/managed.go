// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	DeploymentModeManagedEnterprise = "managed_enterprise"
	ConfigPathEnv                   = "DEFENSECLAW_CONFIG"
	DeploymentModeEnv               = "DEFENSECLAW_DEPLOYMENT_MODE"
	HookGuardianAuthorizationDirEnv = "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"
	HookGuardianAuthorizationFile   = "protected_targets.json"
	// HookGuardianUserCleanupFile, next to the authorization ledger, lists
	// the DefenseClaw per-user registrations the hook guardian still has to
	// remove from the homes of users it no longer enrolls.
	HookGuardianUserCleanupFile = "user-cleanup.json"
	// HookGuardianCredentialAttestationFile, next to the ledger, is the
	// standalone Unix guardian's root-only record of what its last reconcile
	// did to each target and which per-user credential key it rendered from
	// (enterprisehooks.CredentialAttestation).
	HookGuardianCredentialAttestationFile = "credential-attestation.json"
	// HookGuardianReconcileLockFile, next to the ledger, serializes the
	// standalone Unix guardian's reconciles with each other and with a
	// credential rotation staging or committing a key.
	HookGuardianReconcileLockFile = "reconcile.lock"
	// WindowsServiceAccountEnv identifies the exact virtual service account
	// permitted to write the managed runtime tree. It is installed in the
	// administrator-owned per-service registry Environment value; it never
	// broadens config, manifest, binary, or authorization-ledger trust.
	WindowsServiceAccountEnv = "DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT"

	// UnixServiceAccountEnv is the optional unix counterpart to
	// WindowsServiceAccountEnv. When unset, trust checks fall back to
	// the "defenseclaw" service username the installer creates by
	// convention. Setting this env overrides the fallback so a custom
	// packaging that runs the service under a different username can
	// pass ValidateTrustedServiceRuntimeDir without patching the source.
	UnixServiceAccountEnv = "DEFENSECLAW_UNIX_SERVICE_ACCOUNT"
)

func IsManagedEnterprise(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), DeploymentModeManagedEnterprise)
}

func HookGuardianAuthorizationDir(dataDir string) string {
	if configured := strings.TrimSpace(os.Getenv(HookGuardianAuthorizationDirEnv)); configured != "" {
		return filepath.Clean(configured)
	}
	return filepath.Clean(strings.TrimSpace(dataDir)) + "-hook-guardian"
}

func HookGuardianAuthorizationPath(dataDir string) string {
	return filepath.Join(HookGuardianAuthorizationDir(dataDir), HookGuardianAuthorizationFile)
}
