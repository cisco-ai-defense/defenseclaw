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

type windowsCopilotUserRuntimeTransaction struct {
	home           string
	dataDir        string
	hookDir        string
	paths          []string
	snapshot       []windowsRuntimeFileSnapshot
	targetSID      *windows.SID
	createdDataDir bool
	createdHookDir bool
}

func installWindowsCopilotManagedResult(_ context.Context, opts InstallOptions) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseManagedAgentVersion("copilot", opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	if strings.TrimSpace(opts.HookContractID) == "" {
		opts.HookContractID = connector.CopilotEnterpriseHookContractID
	}
	if opts.HookContractID != connector.CopilotEnterpriseHookContractID {
		return InstallResult{}, fmt.Errorf("enterprise hooks: Copilot requires hook contract %s", connector.CopilotEnterpriseHookContractID)
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	if _, ok := target.conn.(*connector.CopilotConnector); !ok {
		return InstallResult{}, errors.New("enterprise hooks: Copilot target is not the certified built-in enterprise connector")
	}
	target.setup.HookFailMode = "open"
	target.setup.HookContractID = connector.CopilotEnterpriseHookContractID
	policyPaths, err := windowsCopilotManagedPathsResolve()
	if err != nil {
		return InstallResult{}, err
	}
	transaction := windowsCopilotUserRuntimeTransaction{
		home:      target.home,
		dataDir:   target.dataDir,
		hookDir:   filepath.Join(target.dataDir, "hooks"),
		paths:     windowsCopilotRuntimePaths(target.dataDir),
		targetSID: target.sid,
	}
	var lockEntry connector.HookContractLockEntry
	var lockUpdatedAt, entryUpdatedAt string
	var generation WindowsManagedRuntimeGenerationPublication
	err = connector.WithUserHomeDir(target.home, func() error {
		return windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
			verifiedHome, verifiedSID, err := validateWindowsEnterpriseHome(target.home, target.sid.String())
			if err != nil {
				return err
			}
			if !sameWindowsEnterprisePath(verifiedHome, target.home) || !verifiedSID.Equals(target.sid) {
				return errors.New("enterprise hooks: Copilot target profile identity changed before runtime mutation")
			}
			if err := prepareWindowsCopilotRuntime(transaction, opts.AllowMissingHookConfigRepair); err != nil {
				return err
			}
			transaction.snapshot, err = snapshotWindowsRuntimeFiles(transaction.paths)
			if err != nil {
				return err
			}
			fail := func(cause error) error {
				if restoreErr := restoreWindowsCopilotUserRuntime(transaction); restoreErr != nil {
					return fmt.Errorf("%v (Copilot runtime rollback failed: %v)", cause, restoreErr)
				}
				return cause
			}
			creation, createErr := ensureWindowsTargetOwnedDirectoryTree(transaction.home, transaction.hookDir, transaction.targetSID)
			transaction.createdDataDir = creation.createdDataDir
			transaction.createdHookDir = creation.createdHookDir
			if createErr != nil {
				return fail(fmt.Errorf("enterprise hooks: create Copilot managed runtime: %w", createErr))
			}
			if err := connector.ReconcileManagedNativeHookRuntime(target.dataDir, target.setup.APIAddr, "copilot", target.setup.HookAPIToken); err != nil {
				return fail(fmt.Errorf("enterprise hooks: write Copilot managed runtime: %w", err))
			}
			lockEntry, err = connector.NewHookContractLockEntryForMode(target.setup, target.conn, version.Current().BinaryVersion, true)
			if err != nil {
				return fail(fmt.Errorf("enterprise hooks: build Copilot managed hook contract: %w", err))
			}
			lockEntry.HookFailMode = "open"
			lockEntry.HookScriptDigests = nil
			lockEntry.Locations = connector.ConnectorLocations{HookConfigPaths: []string{policyPaths.Policy}}
			if err := connector.SaveRecoveredHookContractLockEntryForMode(target.dataDir, lockEntry, opts.RecoveryHookContractLockUpdatedAt, opts.RecoveryHookContractEntryUpdatedAt); err != nil {
				return fail(fmt.Errorf("enterprise hooks: save Copilot managed hook contract: %w", err))
			}
			lockUpdatedAt, entryUpdatedAt, err = connector.ManagedHookContractTimestamps(target.dataDir, "copilot")
			if err != nil {
				return fail(fmt.Errorf("enterprise hooks: load Copilot hook contract recovery state: %w", err))
			}
			if err := hardenWindowsUserRuntime(target.home, target.dataDir, transaction.paths, target.sid); err != nil {
				return fail(err)
			}
			if err := verifyWindowsCopilotUserRuntime(target, policyPaths.Policy); err != nil {
				return fail(err)
			}
			generation, err = prepareWindowsManagedRuntimeGenerationForInstall(
				"copilot", target.sid, target.dataDir, target.hookExecutable,
				target.setup.APIAddr, target.setup.HookAPIToken, lockEntry.ContractID,
				lockUpdatedAt, entryUpdatedAt,
			)
			if err != nil {
				return fail(fmt.Errorf("enterprise hooks: prepare immutable Copilot runtime generation: %w", err))
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
			fmt.Errorf("enterprise hooks: select immutable Copilot runtime generation: %w", err),
			discardWindowsManagedRuntimeGeneration(generation),
			windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error { return restoreWindowsCopilotUserRuntime(transaction) }),
		)
	}
	rollbackMachine, err := installWindowsCopilotManagedPolicy(target.setup, target.sid, target.dataDir)
	if err != nil {
		return InstallResult{}, errors.Join(
			err,
			rollbackWindowsManagedRuntimeGeneration(generationCommit, generation),
			windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error { return restoreWindowsCopilotUserRuntime(transaction) }),
		)
	}
	if err := verifyWindowsCopilotMachineTarget(target); err != nil {
		var rollbackErrors []error
		machineOK := true
		if rollbackMachine != nil {
			if rollbackErr := rollbackMachine(); rollbackErr != nil {
				machineOK = false
				rollbackErrors = append(rollbackErrors, rollbackErr)
			}
		}
		if machineOK {
			if rollbackErr := rollbackWindowsManagedRuntimeGeneration(generationCommit, generation); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, rollbackErr)
			} else if rollbackErr := windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error { return restoreWindowsCopilotUserRuntime(transaction) }); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, rollbackErr)
			}
		}
		return InstallResult{}, errors.Join(append([]error{err}, rollbackErrors...)...)
	}
	return InstallResult{
		Connector:                  "copilot",
		UserHome:                   target.home,
		DataDir:                    target.dataDir,
		HookConfigPaths:            []string{policyPaths.Policy},
		CreatedDirs:                []string{transaction.dataDir, transaction.hookDir},
		AgentVersion:               target.setup.AgentVersion,
		HookContractID:             lockEntry.ContractID,
		HookContractLockUpdatedAt:  lockUpdatedAt,
		HookContractEntryUpdatedAt: entryUpdatedAt,
	}, nil
}

func verifyWindowsCopilotManagedResult(_ context.Context, opts InstallOptions) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseManagedAgentVersion("copilot", opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	if strings.TrimSpace(opts.HookContractID) == "" {
		opts.HookContractID = connector.CopilotEnterpriseHookContractID
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	target.setup.HookFailMode = "open"
	target.setup.HookContractID = connector.CopilotEnterpriseHookContractID
	paths, err := windowsCopilotManagedPathsResolve()
	if err != nil {
		return InstallResult{}, err
	}
	if err := verifyWindowsCopilotUserRuntime(target, paths.Policy); err != nil {
		return InstallResult{}, err
	}
	if err := verifyWindowsCopilotMachineTarget(target); err != nil {
		return InstallResult{}, err
	}
	lock, err := connector.LoadHookContractLockEntryForMode(target.dataDir, "copilot", true)
	if err != nil {
		return InstallResult{}, err
	}
	lockUpdatedAt, entryUpdatedAt, err := connector.ManagedHookContractTimestamps(target.dataDir, "copilot")
	if err != nil {
		return InstallResult{}, err
	}
	if err := verifyWindowsManagedRuntimeGenerationForInstall(
		"copilot", target.sid, target.dataDir, target.hookExecutable,
		target.setup.APIAddr, target.setup.HookAPIToken, lock.ContractID,
		lockUpdatedAt, entryUpdatedAt,
	); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{
		Connector:       "copilot",
		UserHome:        target.home,
		DataDir:         target.dataDir,
		HookConfigPaths: []string{paths.Policy},
		CreatedDirs:     []string{target.dataDir, filepath.Join(target.dataDir, "hooks")},
		AgentVersion:    lock.RawAgentVersion,
		HookContractID:  lock.ContractID,
	}, nil
}

func prepareWindowsCopilotRuntime(transaction windowsCopilotUserRuntimeTransaction, allowRepair bool) error {
	for _, dir := range []string{transaction.dataDir, transaction.hookDir} {
		if err := prepareWindowsGenericPath(transaction.home, dir, transaction.targetSID, true, false, allowRepair, "Copilot managed runtime directory"); err != nil {
			return err
		}
	}
	for _, path := range transaction.paths {
		if err := prepareWindowsGenericPath(transaction.home, path, transaction.targetSID, false, false, allowRepair, "Copilot managed runtime file"); err != nil {
			return err
		}
	}
	return validateWindowsUserPathPrefix(transaction.home, transaction.dataDir, transaction.targetSID, true)
}

func verifyWindowsCopilotUserRuntime(target windowsGenericManagedTarget, policyPath string) error {
	if err := verifyWindowsUserRuntime(windowsCopilotRuntimePaths(target.dataDir), target.sid); err != nil {
		return err
	}
	if err := connector.ValidateManagedNativeHookRuntime(target.dataDir, target.setup.APIAddr, "copilot"); err != nil {
		return fmt.Errorf("enterprise hooks: Copilot managed runtime is invalid: %w", err)
	}
	tokenPath, err := connector.HookTokenFilePath(filepath.Join(target.dataDir, "hooks"), "copilot")
	if err != nil {
		return err
	}
	tokenBody, err := connector.ReadManagedHookRuntimeFile(tokenPath, "Copilot connector-scoped token", windowsEnterpriseTokenMaxBytes)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(tokenBody))), []byte(target.setup.HookAPIToken)) != 1 {
		return errors.New("enterprise hooks: Copilot connector-scoped token does not match the protected service token")
	}
	lock, err := connector.LoadHookContractLockEntryForMode(target.dataDir, "copilot", true)
	if err != nil {
		return err
	}
	if err := connector.ValidateWindowsManagedHookContractGatewayServiceBinding(lock); err != nil {
		return err
	}
	if lock.Connector != "copilot" || lock.ContractID != connector.CopilotEnterpriseHookContractID ||
		len(lock.Locations.HookConfigPaths) != 1 || !sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], policyPath) ||
		len(lock.Locations.HookScriptPaths) != 0 || len(lock.HookScriptDigests) != 0 ||
		!strings.EqualFold(strings.TrimSpace(lock.HookFailMode), "open") {
		return errors.New("enterprise hooks: Copilot managed hook contract is noncanonical")
	}
	return nil
}

func verifyWindowsCopilotMachineTarget(target windowsGenericManagedTarget) error {
	if err := verifyWindowsCopilotManagedPolicyTarget(target.setup, target.sid, target.dataDir); err != nil {
		return err
	}
	return nil
}

func windowsCopilotRuntimePaths(dataDir string) []string {
	hookDir := filepath.Join(dataDir, "hooks")
	return []string{
		filepath.Join(hookDir, ".token"),
		filepath.Join(hookDir, ".hookcfg"),
		filepath.Join(hookDir, ".hookcfg.copilot"),
		filepath.Join(hookDir, ".hookcfg.lock"),
		filepath.Join(hookDir, ".hook-copilot.token"),
		filepath.Join(dataDir, "hook_contract_lock.json"),
		filepath.Join(dataDir, "hook_contract_lock.json.lock"),
	}
}

func restoreWindowsCopilotUserRuntime(transaction windowsCopilotUserRuntimeTransaction) error {
	if err := restoreWindowsRuntimeFiles(transaction.home, transaction.targetSID, transaction.snapshot); err != nil {
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
