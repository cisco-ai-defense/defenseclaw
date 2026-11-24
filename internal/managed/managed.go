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
	"runtime"
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
	// HookGuardianEnrolledAccountsFile, next to the authorization ledger,
	// lists every account the hook guardian has protected. An account stays
	// in it after its last ledger row is gone, until its account or profile
	// is removed, so it is never again a first adoption (GAP-1733 review 2).
	HookGuardianEnrolledAccountsFile = "enrolled-accounts.json"
	// HookGuardianCredentialAttestationFile, next to the ledger, is the
	// standalone Unix guardian's root-only record of what its last reconcile
	// did to each target and which per-user credential key it rendered from
	// (enterprisehooks.CredentialAttestation).
	HookGuardianCredentialAttestationFile = "credential-attestation.json"
	// HookGuardianRefusedSurfacesFile, next to the ledger, lists the
	// (user, connector) pairs whose only installs are app or extension
	// surfaces refused under enterprise.enrollment.unverified_versions:
	// refuse. The standalone Unix enumerator writes it with the ledger's
	// ownership and mode; the gateway refuses those hook calls.
	HookGuardianRefusedSurfacesFile = "refused-surfaces.json"
	// HookGuardianUnprotectedAgentsFile, next to the ledger, is the gateway's
	// copy of the enumerator's root-only unprotected-agents record: the same
	// agents from the same scan, so the caller's own status says what the
	// administrator's status says. The standalone Unix enumerator writes it
	// with the ledger's ownership and mode.
	HookGuardianUnprotectedAgentsFile = "unprotected-agents.json"
	// HookGuardianAgentVersionsFile, next to the ledger, lists the agent
	// version the standalone Unix enumerator last verified per account and
	// connector, in the ledger's target shape. A Linux or macOS
	// machine-policy connector has no per-user guardian row, so the gateway
	// reads the caller's version here (rel-1-0-10:GAP-0114).
	HookGuardianAgentVersionsFile = "agent-versions.json"
	// HookGuardianCredentialTransactionFile, next to the ledger, is the
	// root-only record of the per-user credential rotation in progress
	// (enterprisehooks.CredentialTransaction). The standalone Unix guardian
	// renders from a staged key only while it names that key.
	HookGuardianCredentialTransactionFile = "credential-transaction.json"
	// HookGuardianReconcileLockFile, next to the ledger, serializes the
	// standalone Unix guardian's reconciles with each other and with a
	// credential rotation staging or committing a key, and on Windows the
	// guardian state writers (the service and an administrator reconcile).
	HookGuardianReconcileLockFile = "reconcile.lock"
	// WindowsServiceAccountEnv names the gateway service SID, as its
	// `NT SERVICE\<name>` account, permitted to write the managed runtime
	// tree. The gateway logs on as LocalSystem and carries this SID in its
	// write-restricted token; 1.0.0 logged on as the account itself. It is
	// installed in the administrator-owned per-service registry Environment
	// value; it never broadens config, manifest, binary, or
	// authorization-ledger trust.
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

// HookGuardianAuthorizationDir is the hook guardian's authorization folder,
// which holds its protection ledger, for dataDir: the
// DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR override; else, when dataDir is this
// platform's standalone layout data folder, that layout's GuardianAuthDir;
// else <dataDir>-hook-guardian. A process started without the service pins
// (status as an administrator, a manual reconcile or verify) therefore reads
// the ledger the guardian writes. On Windows and macOS the layout folder is
// not <dataDir>-hook-guardian, and such a reader found no ledger, so it
// counted no account as enrolled (rel-1-0-10 GAP-1733 review).
func HookGuardianAuthorizationDir(dataDir string) string {
	if configured := strings.TrimSpace(os.Getenv(HookGuardianAuthorizationDirEnv)); configured != "" {
		return filepath.Clean(configured)
	}
	return hookGuardianAuthorizationDirFor(runtime.GOOS, dataDir)
}

// hookGuardianAuthorizationDirFor is the authorization directory of dataDir
// on goos when HookGuardianAuthorizationDirEnv is unset: <data_dir>-hook-guardian,
// except for the data directory of the macOS standalone layout, whose
// lifecycle creates the directory as hook-guardian-state beside it (the
// layout's GuardianAuthDir) and whose launchd services get that path from
// their plists. An administrator shell has no such variable, so a command
// run there (config validate) read /opt/cisco/defenseclaw/runtime-hook-guardian,
// which does not exist, found no guardian identity records and warned that
// a group budget the gateway applies selects nobody (rel-1-0-10:GAP-1541).
//
// The Windows standalone layout has the same shape: its PowerShell lifecycle
// creates <ProgramData>\Cisco\DefenseClaw\hook-guardian-state beside the
// runtime data directory and gives its services the path in their registry
// Environment, so an administrator shell read runtime-hook-guardian there
// (rel-1-0-10:GAP-1739). Its roots come from the protected HKLM registration
// (standaloneWindowsAuthLayout), never from the caller's environment.
func hookGuardianAuthorizationDirFor(goos, dataDir string) string {
	clean := filepath.Clean(strings.TrimSpace(dataDir))
	switch goos {
	case "darwin":
		if layout, err := StandaloneLayoutFor(goos); err == nil && clean == layout.DataDir {
			return layout.GuardianAuthDir
		}
	case "windows":
		// Only a ...\runtime directory can be the layout's, so a per-user
		// data directory reads no registration.
		trimmed := strings.TrimRight(clean, `\/`)
		if !strings.HasSuffix(strings.ToLower(trimmed), `\runtime`) {
			break
		}
		if layout, err := standaloneWindowsAuthLayout(); err == nil && strings.EqualFold(trimmed, layout.DataDir) {
			return layout.GuardianAuthDir
		}
	}
	return clean + "-hook-guardian"
}

// standaloneWindowsAuthLayout is the Windows standalone layout of the trusted
// HKLM Program Files and ProgramData roots, for hookGuardianAuthorizationDirFor.
// Tests replace it.
var standaloneWindowsAuthLayout = func() (StandaloneLayout, error) {
	programFiles, programData, err := TrustedStandaloneWindowsRoots()
	if err != nil {
		return StandaloneLayout{}, err
	}
	return StandaloneWindowsLayoutForRoots(programFiles, programData)
}

// HookGuardianAuthorizationDirForLayout is that folder for a standalone
// layout: the DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR override, else
// layout.GuardianAuthDir, or "" when neither is set.
func HookGuardianAuthorizationDirForLayout(layout StandaloneLayout) string {
	if configured := strings.TrimSpace(os.Getenv(HookGuardianAuthorizationDirEnv)); configured != "" {
		return filepath.Clean(configured)
	}
	if dir := strings.TrimSpace(layout.GuardianAuthDir); dir != "" {
		return filepath.Clean(dir)
	}
	return ""
}

// ForeignHookCleanDirSuffix names the folder next to the data directory in
// which the Linux and macOS standalone gateway publishes, read-only, the
// agent processes its last foreign-hook session exchange answered allow for
// (enterprisepolicy.WriteForeignHookCleanMirrors). The lifecycle creates it
// 0711 for the service account.
const ForeignHookCleanDirSuffix = "-foreign-hook-clean"

// ForeignHookCleanDir is that folder for dataDir, or "" when dataDir is not
// an absolute path.
func ForeignHookCleanDir(dataDir string) string {
	dataDir = strings.TrimSpace(dataDir)
	if !filepath.IsAbs(dataDir) {
		return ""
	}
	return filepath.Clean(dataDir) + ForeignHookCleanDirSuffix
}

func HookGuardianAuthorizationPath(dataDir string) string {
	return filepath.Join(HookGuardianAuthorizationDir(dataDir), HookGuardianAuthorizationFile)
}
