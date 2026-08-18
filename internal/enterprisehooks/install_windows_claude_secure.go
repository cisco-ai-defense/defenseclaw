//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"golang.org/x/sys/windows"
)

type windowsClaudeUserRuntimeTransaction struct {
	home           string
	dataDir        string
	hookDir        string
	paths          []string
	snapshot       []windowsRuntimeFileSnapshot
	targetSID      *windows.SID
	createdDataDir bool
	createdHookDir bool
}

func installWindowsClaudeManagedResultSecure(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseAgentVersion(opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(opts.ConnectorName), "claudecode") {
		return InstallResult{}, fmt.Errorf("enterprise hooks: native Windows managed policy requires connector claudecode")
	}
	targetSID, err := validateWindowsEnterpriseTargetSID(opts.OwnerSID)
	if err != nil {
		return InstallResult{}, err
	}
	registry := opts.Registry
	if registry == nil {
		registry = newWindowsEnterpriseConnectorRegistry()
	}
	conn, ok := registry.Get("claudecode")
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: unknown connector %q", "claudecode")
	}
	if err := windowsEnterpriseConnectorCertification("claudecode", conn); err != nil {
		return InstallResult{}, err
	}
	provider, ok := conn.(connector.ManagedHookPolicyProvider)
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q does not expose a managed policy contract", conn.Name())
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return InstallResult{}, err
	}
	if !filepath.IsAbs(hookExecutable) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: managed hook executable is not absolute: %s", hookExecutable)
	}
	hookExecutable = filepath.Clean(hookExecutable)
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: managed hook executable trust check failed: %w", err)
	}
	policyPath, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return InstallResult{}, err
	}

	setup := connector.SetupOpts{
		ProxyAddr:          strings.TrimSpace(opts.ProxyAddr),
		APIAddr:            strings.TrimSpace(opts.APIAddr),
		APIToken:           strings.TrimSpace(opts.APIToken),
		HookAPIToken:       strings.TrimSpace(opts.APIToken),
		HookAPITokenScoped: true,
		OTLPPathToken:      strings.TrimSpace(opts.OTLPPathToken),
		Interactive:        false,
		ManagedEnterprise:  true,
		WorkspaceDir:       strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:       windowsEnterpriseHookFailMode("claudecode", opts.HookFailMode),
		HILTEnabled:        opts.HILTEnabled,
		AgentVersion:       strings.TrimSpace(opts.AgentVersion),
		HookContractID:     strings.TrimSpace(opts.HookContractID),
		HookExecutable:     hookExecutable,
	}
	if err := validateWindowsEnterpriseImpersonationSetup(setup); err != nil {
		return InstallResult{}, err
	}
	if setup.APIAddr == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: API address is required")
	}
	if setup.HookAPIToken == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector-scoped hook token is required")
	}

	var (
		home           string
		policyBody     []byte
		lockEntry      connector.HookContractLockEntry
		lockUpdatedAt  string
		entryUpdatedAt string
		hookScripts    []string
		transaction    windowsClaudeUserRuntimeTransaction
	)
	err = windowsEnterpriseTargetImpersonation(targetSID, opts.UserHome, func() error {
		verifiedHome, verifiedSID, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
		if err != nil {
			return err
		}
		if !verifiedSID.Equals(targetSID) {
			return fmt.Errorf("enterprise hooks: verified profile SID %s does not match manifest SID %s", verifiedSID, targetSID)
		}
		home = verifiedHome
		setup.DataDir, err = resolveWindowsEnterpriseDataDir(home, opts.DataDir)
		if err != nil {
			return err
		}
		if err := prepareWindowsGenericPath(
			home,
			setup.DataDir,
			targetSID,
			true,
			false,
			opts.AllowMissingHookConfigRepair,
			"Claude data dir",
		); err != nil {
			return err
		}
		if err := requireWindowsEnterpriseAgentVersion(setup.AgentVersion); err != nil {
			return err
		}
		if setup.HookContractID == "" {
			resolution := connector.ResolveHookContract(conn.Name(), setup.AgentVersion)
			setup.HookContractID = resolution.Contract.ContractID
		}
		if err := validateHookContract(opts.GuardrailMode, conn, setup); err != nil {
			return err
		}
		policyBody, err = provider.ManagedHookPolicy(setup)
		if err != nil {
			return fmt.Errorf("enterprise hooks: build Claude Code managed policy: %w", err)
		}
		if err := provider.VerifyManagedHookPolicy(policyBody, setup); err != nil {
			return fmt.Errorf("enterprise hooks: verify rendered Claude Code managed policy: %w", err)
		}

		transaction = windowsClaudeUserRuntimeTransaction{
			home:      home,
			dataDir:   setup.DataDir,
			hookDir:   filepath.Join(setup.DataDir, "hooks"),
			paths:     windowsClaudeRuntimePaths(setup, conn),
			targetSID: targetSID,
		}
		for _, path := range transaction.paths {
			if !pathInside(home, filepath.Clean(path)) {
				return fmt.Errorf("enterprise hooks: refusing Claude runtime path outside target profile: %s", path)
			}
		}
		if err := prepareWindowsGenericPath(
			home,
			transaction.hookDir,
			targetSID,
			true,
			false,
			opts.AllowMissingHookConfigRepair,
			"Claude hook dir",
		); err != nil {
			return err
		}
		for _, path := range transaction.paths {
			if err := prepareWindowsGenericPath(
				home,
				path,
				targetSID,
				false,
				false,
				opts.AllowMissingHookConfigRepair,
				"Claude runtime file",
			); err != nil {
				return err
			}
		}
		if err := validateWindowsUserPathPrefix(home, setup.DataDir, targetSID, true); err != nil {
			return err
		}
		transaction.snapshot, err = snapshotWindowsRuntimeFiles(transaction.paths)
		if err != nil {
			return err
		}
		if _, statErr := os.Lstat(transaction.dataDir); errors.Is(statErr, os.ErrNotExist) {
			transaction.createdDataDir = true
		} else if statErr != nil {
			return fmt.Errorf("enterprise hooks: inspect per-user data directory: %w", statErr)
		}
		if _, statErr := os.Lstat(transaction.hookDir); errors.Is(statErr, os.ErrNotExist) {
			transaction.createdHookDir = true
		} else if statErr != nil {
			return fmt.Errorf("enterprise hooks: inspect per-user hook directory: %w", statErr)
		}
		fail := func(cause error) error {
			if restoreErr := restoreWindowsClaudeUserRuntime(transaction); restoreErr != nil {
				return fmt.Errorf("%v (per-user runtime rollback failed: %v)", cause, restoreErr)
			}
			return cause
		}
		if err := os.MkdirAll(transaction.hookDir, 0o700); err != nil {
			return fail(fmt.Errorf("enterprise hooks: create per-user hook runtime: %w", err))
		}
		if err := connector.WriteHookScriptsForConnectorObjectWithOpts(transaction.hookDir, setup, conn); err != nil {
			return fail(fmt.Errorf("enterprise hooks: write managed Claude Code hook runtime: %w", err))
		}
		lockEntry, err = connector.NewHookContractLockEntryForMode(
			setup,
			conn,
			version.Current().BinaryVersion,
			true,
		)
		if err != nil {
			return fail(fmt.Errorf(
				"enterprise hooks: digest managed Claude Code runtime: %w",
				err,
			))
		}
		lockEntry.Locations.HookConfigPaths = []string{policyPath}
		if err := connector.SaveRecoveredHookContractLockEntryForMode(
			setup.DataDir,
			lockEntry,
			opts.RecoveryHookContractLockUpdatedAt,
			opts.RecoveryHookContractEntryUpdatedAt,
		); err != nil {
			return fail(fmt.Errorf("enterprise hooks: save hook contract lock: %w", err))
		}
		lockUpdatedAt, entryUpdatedAt, err =
			connector.ManagedHookContractTimestamps(
				setup.DataDir,
				conn.Name(),
			)
		if err != nil {
			return fail(fmt.Errorf(
				"enterprise hooks: load protected hook contract recovery state: %w",
				err,
			))
		}
		if err := hardenWindowsUserRuntime(home, setup.DataDir, transaction.paths, targetSID); err != nil {
			return fail(err)
		}
		if err := verifyWindowsUserRuntime(transaction.paths, targetSID); err != nil {
			return fail(err)
		}
		if err := connector.ValidateManagedNativeHookRuntime(
			setup.DataDir,
			setup.APIAddr,
			conn.Name(),
		); err != nil {
			return fail(fmt.Errorf("enterprise hooks: managed hook runtime sidecars are invalid: %w", err))
		}
		tokenPath := filepath.Join(setup.DataDir, "hooks", ".hook-claudecode.token")
		tokenBody, err := connector.ReadManagedHookRuntimeFile(
			tokenPath,
			"Claude Code connector-scoped token",
			windowsEnterpriseTokenMaxBytes,
		)
		if err != nil {
			return fail(fmt.Errorf("enterprise hooks: read per-user connector-scoped token: %w", err))
		}
		if subtle.ConstantTimeCompare(
			[]byte(strings.TrimSpace(string(tokenBody))),
			[]byte(setup.HookAPIToken),
		) != 1 {
			return fail(fmt.Errorf("enterprise hooks: per-user connector-scoped token does not match the protected service token"))
		}
		if scriptProvider, ok := conn.(connector.HookScriptProvider); ok {
			hookScripts = scriptProvider.HookScripts(setup)
		}
		return nil
	})
	if err != nil {
		return InstallResult{}, err
	}

	installedPolicyPath, rollbackPolicy, err := installWindowsClaudeManagedPolicy(policyBody, setup, targetSID)
	if err != nil {
		if restoreErr := restoreWindowsClaudeUserRuntimeAsTarget(targetSID, home, transaction); restoreErr != nil {
			return InstallResult{}, fmt.Errorf("%v (per-user runtime rollback failed: %v)", err, restoreErr)
		}
		return InstallResult{}, err
	}
	rollbackAll := func(cause error) error {
		if rollbackPolicy != nil {
			if policyErr := rollbackPolicy(); policyErr != nil {
				cause = fmt.Errorf("%v (managed policy rollback failed: %v)", cause, policyErr)
			}
		}
		if restoreErr := restoreWindowsClaudeUserRuntimeAsTarget(targetSID, home, transaction); restoreErr != nil {
			cause = fmt.Errorf("%v (per-user runtime rollback failed: %v)", cause, restoreErr)
		}
		return cause
	}
	if !sameWindowsEnterprisePath(installedPolicyPath, policyPath) {
		return InstallResult{}, rollbackAll(fmt.Errorf(
			"enterprise hooks: installed Claude policy path %s changed from validated path %s",
			installedPolicyPath,
			policyPath,
		))
	}
	persistedPolicy, err := os.ReadFile(policyPath)
	if err != nil {
		return InstallResult{}, rollbackAll(fmt.Errorf("enterprise hooks: read persisted Claude Code managed policy: %w", err))
	}
	if err := provider.VerifyManagedHookPolicy(persistedPolicy, setup); err != nil {
		return InstallResult{}, rollbackAll(fmt.Errorf("enterprise hooks: persisted Claude Code managed policy is inactive: %w", err))
	}
	if err := verifyWindowsClaudeManagedPolicy(policyPath, policyBody); err != nil {
		return InstallResult{}, rollbackAll(err)
	}
	if err := windowsEnterpriseTargetImpersonation(targetSID, home, func() error {
		cleanupWindowsManagedObstructionQuarantine(transaction.dataDir, targetSID)
		cleanupWindowsManagedObstructionQuarantine(transaction.hookDir, targetSID)
		for _, path := range transaction.paths {
			cleanupWindowsManagedObstructionQuarantine(path, targetSID)
		}
		return nil
	}); err != nil {
		return InstallResult{}, rollbackAll(fmt.Errorf("enterprise hooks: clean repaired runtime obstructions: %w", err))
	}

	_ = ctx
	return InstallResult{
		Connector:                  conn.Name(),
		UserHome:                   home,
		DataDir:                    setup.DataDir,
		HookConfigPaths:            []string{policyPath},
		HookScripts:                sortedUnique(hookScripts),
		CreatedDirs:                sortedUnique([]string{transaction.dataDir, transaction.hookDir}),
		AgentVersion:               setup.AgentVersion,
		HookContractID:             lockEntry.ContractID,
		HookContractLockUpdatedAt:  lockUpdatedAt,
		HookContractEntryUpdatedAt: entryUpdatedAt,
	}, nil
}

func restoreWindowsClaudeUserRuntimeAsTarget(
	targetSID *windows.SID,
	home string,
	transaction windowsClaudeUserRuntimeTransaction,
) error {
	return windowsEnterpriseTargetImpersonation(targetSID, home, func() error {
		return restoreWindowsClaudeUserRuntime(transaction)
	})
}

func restoreWindowsClaudeUserRuntime(transaction windowsClaudeUserRuntimeTransaction) error {
	if err := restoreWindowsRuntimeFiles(transaction.home, transaction.targetSID, transaction.snapshot); err != nil {
		return err
	}
	if transaction.createdDataDir || transaction.createdHookDir {
		if err := removeEmptyWindowsDirectory(transaction.hookDir); err != nil {
			return err
		}
	}
	if transaction.createdDataDir {
		return removeEmptyWindowsDirectory(transaction.dataDir)
	}
	if transaction.createdHookDir {
		// The hook directory was absent in the transaction preimage and has
		// just been removed. Re-harden only the pre-existing data directory;
		// requiring the absent hook directory here would turn a successful
		// exact rollback into a second, masking failure.
		return prepareWindowsGenericPath(
			transaction.home,
			transaction.dataDir,
			transaction.targetSID,
			true,
			true,
			true,
			"restored per-user data directory",
		)
	}
	return hardenWindowsUserRuntime(transaction.home, transaction.dataDir, transaction.paths, transaction.targetSID)
}

// verifyWindowsClaudeUserRuntimeReadOnly is the elevated operator verification
// path. It must remain side-effect free: repair is exclusively service-mediated
// and runs under the exact target user's token.
func verifyWindowsClaudeUserRuntimeReadOnly(
	home string,
	dataDir string,
	policyPath string,
	targetSID *windows.SID,
	setup connector.SetupOpts,
	conn connector.Connector,
) (connector.HookContractLockEntry, error) {
	var lock connector.HookContractLockEntry
	if _, verifiedSID, err := validateWindowsEnterpriseHome(home, targetSID.String()); err != nil {
		return lock, err
	} else if !verifiedSID.Equals(targetSID) {
		return lock, fmt.Errorf("enterprise hooks: target profile SID changed before verification")
	}
	requiredRuntime := []string{
		filepath.Join(dataDir, "hooks", ".hookcfg"),
		filepath.Join(dataDir, "hooks", ".hookcfg.lock"),
		filepath.Join(dataDir, "hooks", ".hookcfg.claudecode"),
		filepath.Join(dataDir, "hooks", ".hook-claudecode.token"),
		filepath.Join(dataDir, "hook_contract_lock.json"),
		filepath.Join(dataDir, "hook_contract_lock.json.lock"),
	}
	for _, path := range requiredRuntime {
		if err := validateWindowsUserPathElement(path, targetSID, false, false, true); err != nil {
			return lock, fmt.Errorf("enterprise hooks: required managed runtime verification failed for %s: %w", path, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return lock, fmt.Errorf("enterprise hooks: inspect required managed runtime %s: %w", path, err)
		}
		if info.Size() > windowsEnterpriseUserFileMaxBytes {
			return lock, fmt.Errorf(
				"enterprise hooks: required managed runtime %s exceeds %d-byte limit",
				path,
				windowsEnterpriseUserFileMaxBytes,
			)
		}
	}
	if err := validateWindowsUserPathElement(dataDir, targetSID, true, true, true); err != nil {
		return lock, fmt.Errorf("enterprise hooks: managed data directory verification failed: %w", err)
	}
	if err := validateWindowsUserPathElement(filepath.Join(dataDir, "hooks"), targetSID, true, true, true); err != nil {
		return lock, fmt.Errorf("enterprise hooks: managed hook directory verification failed: %w", err)
	}
	tokenBody, err := connector.ReadManagedHookRuntimeFile(
		filepath.Join(dataDir, "hooks", ".hook-claudecode.token"),
		"Claude Code connector-scoped token",
		windowsEnterpriseTokenMaxBytes,
	)
	if err != nil {
		return lock, fmt.Errorf("enterprise hooks: read per-user connector-scoped token: %w", err)
	}
	if subtle.ConstantTimeCompare(
		[]byte(strings.TrimSpace(string(tokenBody))),
		[]byte(setup.HookAPIToken),
	) != 1 {
		return lock, fmt.Errorf("enterprise hooks: per-user connector-scoped token does not match the protected service token")
	}
	if err := connector.ValidateManagedNativeHookRuntime(
		dataDir,
		setup.APIAddr,
		conn.Name(),
	); err != nil {
		return lock, fmt.Errorf("enterprise hooks: managed hook runtime sidecars are invalid: %w", err)
	}
	lock, err = connector.LoadHookContractLockEntryForMode(
		dataDir,
		conn.Name(),
		true,
	)
	if err != nil {
		return lock, fmt.Errorf(
			"enterprise hooks: load managed Claude Code hook contract: %w",
			err,
		)
	}
	if lock.Connector != conn.Name() || len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], policyPath) {
		return lock, fmt.Errorf("enterprise hooks: managed Claude hook contract lock does not identify the active administrator policy")
	}
	current, err := connector.NewHookContractLockEntryForMode(
		setup,
		conn,
		version.Current().BinaryVersion,
		true,
	)
	if err != nil {
		return lock, fmt.Errorf(
			"enterprise hooks: digest managed Claude Code runtime: %w",
			err,
		)
	}
	current.Locations.HookConfigPaths = []string{policyPath}
	if connector.HookContractLockDrifted(lock, current) {
		return lock, fmt.Errorf("enterprise hooks: managed Claude hook contract drift detected")
	}
	if strings.TrimSpace(lock.HookFailMode) != strings.TrimSpace(current.HookFailMode) {
		return lock, fmt.Errorf(
			"enterprise hooks: managed Claude fail mode %q does not match configured mode %q",
			lock.HookFailMode,
			current.HookFailMode,
		)
	}
	return lock, nil
}
