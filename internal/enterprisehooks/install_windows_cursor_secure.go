// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"golang.org/x/sys/windows"
)

type windowsCursorUserRuntimeTransaction struct {
	home           string
	dataDir        string
	hookDir        string
	paths          []string
	snapshot       []windowsRuntimeFileSnapshot
	targetSID      *windows.SID
	createdDataDir bool
	createdHookDir bool
}

func installWindowsCursorManagedResult(
	_ context.Context,
	opts InstallOptions,
) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseManagedAgentVersion("cursor", opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	if target.conn.Name() != "cursor" {
		return InstallResult{}, fmt.Errorf(
			"enterprise hooks: Windows Cursor managed runtime received connector %q",
			target.conn.Name(),
		)
	}
	target.setup.HookFailMode = "closed"
	cursorPaths, err := windowsCursorManagedPaths()
	if err != nil {
		return InstallResult{}, err
	}
	hooksPath := cursorPaths.Hooks
	adapterPath := cursorPaths.Adapter
	transaction := windowsCursorUserRuntimeTransaction{
		home:      target.home,
		dataDir:   target.dataDir,
		hookDir:   filepath.Join(target.dataDir, "hooks"),
		paths:     windowsCursorRuntimePaths(target.dataDir),
		targetSID: target.sid,
	}
	var lockEntry connector.HookContractLockEntry
	var lockUpdatedAt, entryUpdatedAt string
	var generation WindowsManagedRuntimeGenerationPublication
	err = connector.WithUserHomeDir(target.home, func() error {
		return windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
			verifiedHome, verifiedSID, err := validateWindowsEnterpriseHome(
				target.home,
				target.sid.String(),
			)
			if err != nil {
				return err
			}
			if !sameWindowsEnterprisePath(verifiedHome, target.home) || !verifiedSID.Equals(target.sid) {
				return errors.New("enterprise hooks: Cursor target profile identity changed before runtime mutation")
			}
			if err := prepareWindowsCursorRuntime(transaction, opts.AllowMissingHookConfigRepair); err != nil {
				return err
			}
			transaction.snapshot, err = snapshotWindowsRuntimeFiles(transaction.paths)
			if err != nil {
				return err
			}
			fail := func(cause error) error {
				if restoreErr := restoreWindowsCursorUserRuntime(transaction); restoreErr != nil {
					return fmt.Errorf("%v (Cursor runtime rollback failed: %v)", cause, restoreErr)
				}
				return cause
			}
			creation, createErr := ensureWindowsTargetOwnedDirectoryTree(
				transaction.home,
				transaction.hookDir,
				transaction.targetSID,
			)
			transaction.createdDataDir = creation.createdDataDir
			transaction.createdHookDir = creation.createdHookDir
			if createErr != nil {
				return fail(fmt.Errorf("enterprise hooks: create Cursor managed runtime: %w", createErr))
			}
			if err := connector.ReconcileManagedNativeHookRuntime(
				target.dataDir,
				target.setup.APIAddr,
				"cursor",
				target.setup.HookAPIToken,
			); err != nil {
				return fail(fmt.Errorf("enterprise hooks: write Cursor managed runtime: %w", err))
			}
			lockEntry = connector.NewHookContractLockEntry(
				target.setup,
				target.conn,
				version.Current().BinaryVersion,
			)
			lockEntry.HookFailMode = "closed"
			lockEntry.HookScriptDigests = nil
			lockEntry.Locations = connector.ConnectorLocations{
				HookConfigPaths: []string{hooksPath},
				HookScriptPaths: []string{adapterPath},
			}
			if err := connector.SaveRecoveredHookContractLockEntryForMode(
				target.dataDir,
				lockEntry,
				opts.RecoveryHookContractLockUpdatedAt,
				opts.RecoveryHookContractEntryUpdatedAt,
			); err != nil {
				return fail(fmt.Errorf("enterprise hooks: save Cursor managed hook contract: %w", err))
			}
			lockUpdatedAt, entryUpdatedAt, err = connector.ManagedHookContractTimestamps(
				target.dataDir,
				"cursor",
			)
			if err != nil {
				return fail(fmt.Errorf("enterprise hooks: load Cursor hook contract recovery state: %w", err))
			}
			if err := hardenWindowsUserRuntime(
				target.home,
				target.dataDir,
				transaction.paths,
				target.sid,
			); err != nil {
				return fail(err)
			}
			if err := verifyWindowsCursorUserRuntime(target, hooksPath, adapterPath); err != nil {
				return fail(err)
			}
			generation, err = prepareWindowsManagedRuntimeGenerationForInstall(
				"cursor",
				target.sid,
				target.dataDir,
				target.hookExecutable,
				target.setup.APIAddr,
				target.setup.HookAPIToken,
				lockEntry.ContractID,
				lockUpdatedAt,
				entryUpdatedAt,
			)
			if err != nil {
				return fail(fmt.Errorf(
					"enterprise hooks: prepare immutable Cursor runtime generation: %w",
					err,
				))
			}
			return nil
		})
	})
	if err != nil {
		return InstallResult{}, err
	}
	generationCommit, err := windowsManagedRuntimeGenerationCommit(generation)
	if err != nil {
		return InstallResult{}, errors.Join(
			fmt.Errorf("enterprise hooks: select immutable Cursor runtime generation: %w", err),
			discardWindowsManagedRuntimeGeneration(generation),
			windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
				return restoreWindowsCursorUserRuntime(transaction)
			}),
		)
	}
	rollbackMachine, err := installWindowsCursorManagedPolicy(
		target.setup,
		target.sid,
		target.dataDir,
	)
	if err != nil {
		return InstallResult{}, errors.Join(
			err,
			rollbackWindowsManagedRuntimeGeneration(generationCommit, generation),
			windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
				return restoreWindowsCursorUserRuntime(transaction)
			}),
		)
	}
	if err := verifyWindowsCursorMachineTarget(target); err != nil {
		var rollbackErrors []error
		machineRollbackSucceeded := true
		generationRollbackSucceeded := false
		if rollbackMachine != nil {
			if rollbackErr := rollbackMachine(); rollbackErr != nil {
				machineRollbackSucceeded = false
				rollbackErrors = append(rollbackErrors, fmt.Errorf("machine policy: %w", rollbackErr))
			}
		}
		if machineRollbackSucceeded {
			if rollbackErr := rollbackWindowsManagedRuntimeGeneration(
				generationCommit,
				generation,
			); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf(
					"runtime generation: %w",
					rollbackErr,
				))
			} else {
				generationRollbackSucceeded = true
			}
		}
		// If the global policy could not be rolled back, retain the matching
		// protected runtime instead of leaving a live SID enrollment dangling.
		if machineRollbackSucceeded && generationRollbackSucceeded {
			if rollbackErr := windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
				return restoreWindowsCursorUserRuntime(transaction)
			}); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("target runtime: %w", rollbackErr))
			}
		}
		if len(rollbackErrors) != 0 {
			return InstallResult{}, fmt.Errorf(
				"%v (Cursor verification rollback failed: %v)",
				err,
				errors.Join(rollbackErrors...),
			)
		}
		return InstallResult{}, err
	}
	return InstallResult{
		Connector:                  "cursor",
		UserHome:                   target.home,
		DataDir:                    target.dataDir,
		HookConfigPaths:            []string{hooksPath},
		HookScripts:                []string{adapterPath},
		CreatedDirs:                []string{transaction.dataDir, transaction.hookDir},
		AgentVersion:               target.setup.AgentVersion,
		HookContractID:             lockEntry.ContractID,
		HookContractLockUpdatedAt:  lockUpdatedAt,
		HookContractEntryUpdatedAt: entryUpdatedAt,
	}, nil
}

func verifyWindowsCursorManagedResult(
	_ context.Context,
	opts InstallOptions,
) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseManagedAgentVersion("cursor", opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	target.setup.HookFailMode = "closed"
	cursorPaths, err := windowsCursorManagedPaths()
	if err != nil {
		return InstallResult{}, err
	}
	hooksPath := cursorPaths.Hooks
	adapterPath := cursorPaths.Adapter
	if err := verifyWindowsCursorUserRuntime(target, hooksPath, adapterPath); err != nil {
		return InstallResult{}, err
	}
	if err := verifyWindowsCursorMachineTarget(target); err != nil {
		return InstallResult{}, err
	}
	lock, err := connector.LoadHookContractLockEntryForMode(target.dataDir, "cursor", true)
	if err != nil {
		return InstallResult{}, err
	}
	lockUpdatedAt, entryUpdatedAt, err := connector.ManagedHookContractTimestamps(
		target.dataDir,
		"cursor",
	)
	if err != nil {
		return InstallResult{}, fmt.Errorf(
			"enterprise hooks: load protected Cursor runtime generation timestamps: %w",
			err,
		)
	}
	if err := verifyWindowsManagedRuntimeGenerationForInstall(
		"cursor",
		target.sid,
		target.dataDir,
		target.hookExecutable,
		target.setup.APIAddr,
		target.setup.HookAPIToken,
		lock.ContractID,
		lockUpdatedAt,
		entryUpdatedAt,
	); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{
		Connector:       "cursor",
		UserHome:        target.home,
		DataDir:         target.dataDir,
		HookConfigPaths: []string{hooksPath},
		HookScripts:     []string{adapterPath},
		CreatedDirs:     []string{target.dataDir, filepath.Join(target.dataDir, "hooks")},
		AgentVersion:    lock.RawAgentVersion,
		HookContractID:  lock.ContractID,
	}, nil
}

func prepareWindowsCursorRuntime(
	transaction windowsCursorUserRuntimeTransaction,
	allowRepair bool,
) error {
	for _, dir := range []string{transaction.dataDir, transaction.hookDir} {
		if err := prepareWindowsGenericPath(
			transaction.home,
			dir,
			transaction.targetSID,
			true,
			false,
			allowRepair,
			"Cursor managed runtime directory",
		); err != nil {
			return err
		}
	}
	for _, path := range transaction.paths {
		if err := prepareWindowsGenericPath(
			transaction.home,
			path,
			transaction.targetSID,
			false,
			false,
			allowRepair,
			"Cursor managed runtime file",
		); err != nil {
			return err
		}
	}
	return validateWindowsUserPathPrefix(
		transaction.home,
		transaction.dataDir,
		transaction.targetSID,
		true,
	)
}

func verifyWindowsCursorUserRuntime(
	target windowsGenericManagedTarget,
	hooksPath string,
	adapterPath string,
) error {
	if err := verifyWindowsUserRuntime(windowsCursorRuntimePaths(target.dataDir), target.sid); err != nil {
		return err
	}
	if err := connector.ValidateManagedNativeHookRuntime(
		target.dataDir,
		target.setup.APIAddr,
		"cursor",
	); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor managed runtime is invalid: %w", err)
	}
	tokenPath, err := connector.HookTokenFilePath(filepath.Join(target.dataDir, "hooks"), "cursor")
	if err != nil {
		return err
	}
	tokenBody, err := connector.ReadManagedHookRuntimeFile(
		tokenPath,
		"Cursor connector-scoped token",
		windowsEnterpriseTokenMaxBytes,
	)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(
		[]byte(strings.TrimSpace(string(tokenBody))),
		[]byte(target.setup.HookAPIToken),
	) != 1 {
		return errors.New("enterprise hooks: Cursor connector-scoped token does not match the protected service token")
	}
	lock, err := connector.LoadHookContractLockEntryForMode(target.dataDir, "cursor", true)
	if err != nil {
		return err
	}
	if lock.Connector != "cursor" ||
		len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], hooksPath) ||
		len(lock.Locations.HookScriptPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookScriptPaths[0], adapterPath) ||
		len(lock.HookScriptDigests) != 0 ||
		!strings.EqualFold(strings.TrimSpace(lock.HookFailMode), "closed") {
		return errors.New("enterprise hooks: Cursor managed hook contract does not identify only the global enterprise adapter")
	}
	return nil
}

func verifyWindowsCursorMachineTarget(target windowsGenericManagedTarget) error {
	targets, active, err := ReadWindowsCursorManagedPolicyTargets()
	if err != nil {
		return err
	}
	if !active {
		return errors.New("enterprise hooks: Cursor enterprise policy is inactive")
	}
	for _, current := range targets {
		if strings.EqualFold(current.SID, target.sid.String()) &&
			sameWindowsEnterprisePath(current.DataDir, target.dataDir) {
			return nil
		}
	}
	return errors.New("enterprise hooks: Cursor target is absent from the protected machine enrollment")
}

func windowsCursorRuntimePaths(dataDir string) []string {
	hookDir := filepath.Join(dataDir, "hooks")
	return []string{
		filepath.Join(hookDir, ".token"),
		filepath.Join(hookDir, ".hookcfg"),
		filepath.Join(hookDir, ".hookcfg.cursor"),
		filepath.Join(hookDir, ".hookcfg.lock"),
		filepath.Join(hookDir, ".hook-cursor.token"),
		filepath.Join(dataDir, "hook_contract_lock.json"),
		filepath.Join(dataDir, "hook_contract_lock.json.lock"),
	}
}

func restoreWindowsCursorUserRuntime(transaction windowsCursorUserRuntimeTransaction) error {
	if err := restoreWindowsRuntimeFiles(
		transaction.home,
		transaction.targetSID,
		transaction.snapshot,
	); err != nil {
		return err
	}
	if transaction.createdHookDir {
		if err := removeEmptyWindowsDirectory(transaction.hookDir); err != nil {
			return err
		}
	}
	if transaction.createdDataDir {
		return removeEmptyWindowsDirectory(transaction.dataDir)
	}
	return nil
}
