// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

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

var (
	windowsCodexRequirementsOptionsResolver = defaultWindowsCodexRequirementsOptions
	windowsCodexRequirementsReconciler      = connector.ReconcileWindowsCodexMachineRequirements
	windowsCodexRequirementsVerifier        = connector.VerifyWindowsCodexMachineRequirements
)

type windowsCodexUserRuntimeTransaction struct {
	home           string
	dataDir        string
	hookDir        string
	paths          []string
	snapshot       []windowsRuntimeFileSnapshot
	targetSID      *windows.SID
	createdDataDir bool
	createdHookDir bool
}

func installWindowsCodexManagedResult(
	_ context.Context,
	opts InstallOptions,
) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseManagedAgentVersion("codex", opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	if target.conn.Name() != "codex" {
		return InstallResult{}, fmt.Errorf(
			"enterprise hooks: Windows Codex managed runtime received connector %q",
			target.conn.Name(),
		)
	}
	target.setup.HookFailMode = "closed"
	machineOpts, err := windowsCodexRequirementsOptionsResolver(
		target.hookExecutable,
		target.setup.APIAddr,
	)
	if err != nil {
		return InstallResult{}, err
	}
	machineReport, err := windowsCodexRequirementsReconciler(machineOpts)
	if err != nil {
		return InstallResult{}, fmt.Errorf(
			"enterprise hooks: reconcile Codex machine requirements: %w",
			err,
		)
	}
	if !machineReport.OK || !machineReport.SecurityComplete {
		return InstallResult{}, errors.New(
			"enterprise hooks: Codex machine requirements are not security-complete",
		)
	}

	requirementsPath := machineOpts.RequirementsPath
	transaction := windowsCodexUserRuntimeTransaction{
		home:      target.home,
		dataDir:   target.dataDir,
		hookDir:   filepath.Join(target.dataDir, "hooks"),
		paths:     windowsCodexRuntimePaths(target.dataDir),
		targetSID: target.sid,
	}
	var lockEntry connector.HookContractLockEntry
	var lockUpdatedAt string
	var entryUpdatedAt string
	var generation WindowsManagedRuntimeGenerationPublication
	err = connector.WithUserHomeDir(target.home, func() error {
		return windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
			verifiedHome, verifiedSID, verifyErr := validateWindowsEnterpriseHome(
				target.home,
				target.sid.String(),
			)
			if verifyErr != nil {
				return verifyErr
			}
			if !sameWindowsEnterprisePath(verifiedHome, target.home) ||
				!verifiedSID.Equals(target.sid) {
				return errors.New("enterprise hooks: Codex target profile identity changed before runtime mutation")
			}
			if err := prepareWindowsCodexRuntime(
				transaction,
				opts.AllowMissingHookConfigRepair,
			); err != nil {
				return err
			}
			transaction.snapshot, err = snapshotWindowsRuntimeFiles(transaction.paths)
			if err != nil {
				return err
			}
			fail := func(cause error) error {
				if restoreErr := restoreWindowsCodexUserRuntime(transaction); restoreErr != nil {
					return fmt.Errorf("%v (Codex runtime rollback failed: %v)", cause, restoreErr)
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
				return fail(fmt.Errorf("enterprise hooks: create Codex managed runtime: %w", createErr))
			}
			if err := connector.ReconcileManagedNativeHookRuntime(
				target.dataDir,
				target.setup.APIAddr,
				"codex",
				target.setup.HookAPIToken,
			); err != nil {
				return fail(fmt.Errorf("enterprise hooks: write Codex managed runtime: %w", err))
			}
			lockEntry, err = connector.NewHookContractLockEntryForMode(
				target.setup,
				target.conn,
				version.Current().BinaryVersion,
				true,
			)
			if err != nil {
				return fail(fmt.Errorf(
					"enterprise hooks: digest Codex managed runtime: %w",
					err,
				))
			}
			lockEntry.HookFailMode = "closed"
			lockEntry.HookScriptDigests = nil
			lockEntry.Locations = connector.ConnectorLocations{
				HookConfigPaths: []string{requirementsPath},
			}
			if err := connector.SaveRecoveredHookContractLockEntryForMode(
				target.dataDir,
				lockEntry,
				opts.RecoveryHookContractLockUpdatedAt,
				opts.RecoveryHookContractEntryUpdatedAt,
			); err != nil {
				return fail(fmt.Errorf("enterprise hooks: save Codex managed hook contract: %w", err))
			}
			lockUpdatedAt, entryUpdatedAt, err =
				connector.ManagedHookContractTimestamps(
					target.dataDir,
					"codex",
				)
			if err != nil {
				return fail(fmt.Errorf(
					"enterprise hooks: load protected Codex hook contract recovery state: %w",
					err,
				))
			}
			if err := hardenWindowsUserRuntime(
				target.home,
				target.dataDir,
				transaction.paths,
				target.sid,
			); err != nil {
				return fail(err)
			}
			if err := verifyWindowsCodexUserRuntime(
				target,
				requirementsPath,
			); err != nil {
				return fail(err)
			}
			generation, err = prepareWindowsManagedRuntimeGenerationForInstall(
				"codex",
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
					"enterprise hooks: prepare immutable Codex runtime generation: %w",
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
			fmt.Errorf("enterprise hooks: select immutable Codex runtime generation: %w", err),
			discardWindowsManagedRuntimeGeneration(generation),
			windowsEnterpriseTargetImpersonation(
				target.sid,
				target.home,
				func() error { return restoreWindowsCodexUserRuntime(transaction) },
			),
		)
	}
	// Publish this SID only after its target-owned runtime has been hardened and
	// verified. Until this atomic protected-registry update succeeds, direct
	// managed invocation remains fail-closed as an unregistered SID.
	currentTargets, err := connector.ReadWindowsCodexManagedRuntimeTargets(
		target.hookExecutable,
	)
	if err != nil {
		return InstallResult{}, errors.Join(
			err,
			rollbackWindowsManagedRuntimeGeneration(generationCommit, generation),
			windowsEnterpriseTargetImpersonation(
				target.sid,
				target.home,
				func() error { return restoreWindowsCodexUserRuntime(transaction) },
			),
		)
	}
	nextTargets := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(currentTargets)+1)
	for _, current := range currentTargets {
		if strings.EqualFold(current.SID, target.sid.String()) {
			continue
		}
		nextTargets = append(nextTargets, current)
	}
	nextTargets = append(nextTargets, connector.WindowsCodexManagedRuntimeTarget{
		SID:     target.sid.String(),
		DataDir: target.dataDir,
	})
	if err := connector.PublishWindowsCodexManagedRuntimeTargets(
		machineOpts,
		nextTargets,
	); err != nil {
		generationErr := rollbackWindowsManagedRuntimeGeneration(
			generationCommit,
			generation,
		)
		rollbackErr := windowsEnterpriseTargetImpersonation(
			target.sid,
			target.home,
			func() error { return restoreWindowsCodexUserRuntime(transaction) },
		)
		return InstallResult{}, errors.Join(
			fmt.Errorf("enterprise hooks: publish Codex target enrollment: %w", err),
			generationErr,
			rollbackErr,
		)
	}
	return InstallResult{
		Connector:                  "codex",
		UserHome:                   target.home,
		DataDir:                    target.dataDir,
		HookConfigPaths:            []string{requirementsPath},
		CreatedDirs:                []string{transaction.dataDir, transaction.hookDir},
		AgentVersion:               target.setup.AgentVersion,
		HookContractID:             lockEntry.ContractID,
		HookContractLockUpdatedAt:  lockUpdatedAt,
		HookContractEntryUpdatedAt: entryUpdatedAt,
	}, nil
}

func verifyWindowsCodexManagedResult(
	_ context.Context,
	opts InstallOptions,
) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseManagedAgentVersion("codex", opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	target.setup.HookFailMode = "closed"
	machineOpts, err := windowsCodexRequirementsOptionsResolver(
		target.hookExecutable,
		target.setup.APIAddr,
	)
	if err != nil {
		return InstallResult{}, err
	}
	machineReport, err := windowsCodexRequirementsVerifier(machineOpts)
	if err != nil {
		return InstallResult{}, fmt.Errorf(
			"enterprise hooks: verify Codex machine requirements: %w",
			err,
		)
	}
	if !machineReport.OK || !machineReport.SecurityComplete {
		return InstallResult{}, errors.New(
			"enterprise hooks: Codex machine requirements are not security-complete",
		)
	}
	if err := verifyWindowsCodexUserRuntime(target, machineOpts.RequirementsPath); err != nil {
		return InstallResult{}, err
	}
	lock, err := connector.LoadHookContractLockEntryForMode(
		target.dataDir,
		"codex",
		true,
	)
	if err != nil {
		return InstallResult{}, fmt.Errorf(
			"enterprise hooks: load Codex managed hook contract: %w",
			err,
		)
	}
	lockUpdatedAt, entryUpdatedAt, err := connector.ManagedHookContractTimestamps(
		target.dataDir,
		"codex",
	)
	if err != nil {
		return InstallResult{}, fmt.Errorf(
			"enterprise hooks: load protected Codex runtime generation timestamps: %w",
			err,
		)
	}
	if err := verifyWindowsManagedRuntimeGenerationForInstall(
		"codex",
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
		Connector:       "codex",
		UserHome:        target.home,
		DataDir:         target.dataDir,
		HookConfigPaths: []string{machineOpts.RequirementsPath},
		CreatedDirs:     []string{target.dataDir, filepath.Join(target.dataDir, "hooks")},
		AgentVersion:    lock.RawAgentVersion,
		HookContractID:  lock.ContractID,
	}, nil
}

func prepareWindowsCodexRuntime(
	transaction windowsCodexUserRuntimeTransaction,
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
			"Codex managed runtime directory",
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
			"Codex managed runtime file",
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

func verifyWindowsCodexUserRuntime(
	target windowsGenericManagedTarget,
	requirementsPath string,
) error {
	paths := windowsCodexRuntimePaths(target.dataDir)
	if err := verifyWindowsUserRuntime(paths, target.sid); err != nil {
		return err
	}
	if err := connector.ValidateManagedNativeHookRuntime(
		target.dataDir,
		target.setup.APIAddr,
		"codex",
	); err != nil {
		return fmt.Errorf("enterprise hooks: Codex managed runtime is invalid: %w", err)
	}
	tokenPath, err := connector.HookTokenFilePath(
		filepath.Join(target.dataDir, "hooks"),
		"codex",
	)
	if err != nil {
		return err
	}
	tokenBody, err := connector.ReadManagedHookRuntimeFile(
		tokenPath,
		"Codex connector-scoped token",
		windowsEnterpriseTokenMaxBytes,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: read Codex connector-scoped token: %w", err)
	}
	if subtle.ConstantTimeCompare(
		[]byte(strings.TrimSpace(string(tokenBody))),
		[]byte(target.setup.HookAPIToken),
	) != 1 {
		return errors.New("enterprise hooks: Codex connector-scoped token does not match the protected service token")
	}
	lock, err := connector.LoadHookContractLockEntryForMode(
		target.dataDir,
		"codex",
		true,
	)
	if err != nil {
		return fmt.Errorf(
			"enterprise hooks: load Codex managed hook contract: %w",
			err,
		)
	}
	if lock.Connector != "codex" ||
		len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], requirementsPath) ||
		len(lock.Locations.HookScriptPaths) != 0 ||
		!strings.EqualFold(strings.TrimSpace(lock.HookFailMode), "closed") {
		return errors.New("enterprise hooks: Codex managed hook contract does not identify only machine requirements")
	}
	return nil
}

func windowsCodexRuntimePaths(dataDir string) []string {
	hookDir := filepath.Join(dataDir, "hooks")
	return []string{
		filepath.Join(hookDir, ".token"),
		filepath.Join(hookDir, ".hookcfg"),
		filepath.Join(hookDir, ".hookcfg.codex"),
		filepath.Join(hookDir, ".hookcfg.lock"),
		filepath.Join(hookDir, ".hook-codex.token"),
		filepath.Join(dataDir, "hook_contract_lock.json"),
		filepath.Join(dataDir, "hook_contract_lock.json.lock"),
	}
}

func restoreWindowsCodexUserRuntime(
	transaction windowsCodexUserRuntimeTransaction,
) error {
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

func defaultWindowsCodexRequirementsOptions(
	hookExecutable string,
	apiAddr string,
) (connector.WindowsCodexMachineRequirementsOptions, error) {
	var opts connector.WindowsCodexMachineRequirementsOptions
	runtimeDir := strings.TrimSpace(os.Getenv("DEFENSECLAW_HOME"))
	if runtimeDir == "" || !filepath.IsAbs(runtimeDir) ||
		filepath.Clean(runtimeDir) != runtimeDir ||
		!strings.EqualFold(filepath.Base(runtimeDir), "runtime") {
		return opts, errors.New(
			"enterprise hooks: DEFENSECLAW_HOME must be exact protected StateRoot\\runtime",
		)
	}
	stateRoot := filepath.Dir(runtimeDir)
	requirementsPath, err := windowsCodexMachineRequirementsPath()
	if err != nil {
		return opts, err
	}
	applicationControl, err := exactWindowsCodexManagedAttestation(
		connector.WindowsApprovedAgentClientsEnforcedEnv,
	)
	if err != nil {
		return opts, err
	}
	gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(apiAddr)
	if err != nil {
		return opts, err
	}
	gatewayServiceName := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	if err := connector.ValidateWindowsManagedGatewayServiceName(gatewayServiceName); err != nil {
		return opts, err
	}
	opts = connector.WindowsCodexMachineRequirementsOptions{
		RequirementsPath:                requirementsPath,
		ManagedDir:                      filepath.Dir(hookExecutable),
		HookBinary:                      hookExecutable,
		OwnershipPath:                   filepath.Join(stateRoot, "install", "codex-requirements-ownership.json"),
		ManagedStatePath:                filepath.Join(filepath.Dir(requirementsPath), ".defenseclaw-managed-hooks.state"),
		GatewayAddr:                     gatewayAddr,
		GatewayServiceName:              gatewayServiceName,
		AgentApplicationControlEnforced: applicationControl,
		EnterpriseTargetEnabled:         true,
		CodexTargetEnabled:              true,
	}
	return opts, nil
}

func exactWindowsCodexManagedAttestation(name string) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value != "" && value != "1" {
		return false, fmt.Errorf("enterprise hooks: %s must be absent or exactly 1", name)
	}
	return value == "1", nil
}
