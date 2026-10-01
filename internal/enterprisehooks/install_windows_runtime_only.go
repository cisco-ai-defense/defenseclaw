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
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsOpenCodeMachinePolicy reports OpenCode's managed config path and
// whether its machine policy is in force: the guardian installed the trusted
// managed plugin and that config names it. enterprisepolicy owns the check
// but imports this package on Windows, so the CLI installs it with
// SetWindowsOpenCodeMachinePolicy. Unset, OpenCode stays on the per-user
// route.
var windowsOpenCodeMachinePolicy struct {
	sync.Mutex
	check func() (string, bool)
}

// windowsCopilotVSCodeUser places (or, with verify, checks) DefenseClaw's
// VS Code Local hook file and Copilot plugin in a Copilot row's home, as
// the target user. enterprisepolicy owns the files and the CLI resolves
// what the administrator's config wants, so the CLI installs it with
// SetWindowsCopilotVSCodeUser. Unset, Copilot rows leave the home alone.
var windowsCopilotVSCodeUser struct {
	sync.Mutex
	apply func(home string, verify, remove bool) error
}

// SetWindowsCopilotVSCodeUser installs the Copilot VS Code user files hook.
func SetWindowsCopilotVSCodeUser(apply func(home string, verify, remove bool) error) {
	windowsCopilotVSCodeUser.Lock()
	defer windowsCopilotVSCodeUser.Unlock()
	windowsCopilotVSCodeUser.apply = apply
}

func applyWindowsCopilotVSCodeUser(connectorName, home string, verify, remove bool) error {
	if connectorName != "copilot" {
		return nil
	}
	windowsCopilotVSCodeUser.Lock()
	apply := windowsCopilotVSCodeUser.apply
	windowsCopilotVSCodeUser.Unlock()
	if apply == nil {
		return nil
	}
	if err := apply(home, verify, remove); err != nil {
		return fmt.Errorf("enterprise hooks: copilot VS Code Local hooks: %w", err)
	}
	return nil
}

// SetWindowsOpenCodeMachinePolicy installs OpenCode's machine policy check.
func SetWindowsOpenCodeMachinePolicy(check func() (policyPath string, inForce bool)) {
	windowsOpenCodeMachinePolicy.Lock()
	defer windowsOpenCodeMachinePolicy.Unlock()
	windowsOpenCodeMachinePolicy.check = check
}

func windowsOpenCodeMachinePolicyState() (string, bool) {
	windowsOpenCodeMachinePolicy.Lock()
	check := windowsOpenCodeMachinePolicy.check
	windowsOpenCodeMachinePolicy.Unlock()
	if check == nil {
		return "", false
	}
	return check()
}

// windowsOpenCodeMachinePolicyInForce reports whether OpenCode rows install
// only the per-user runtime the managed plugin's hook calls resolve (like
// Copilot) rather than the per-user plugin. Replaced in tests.
var windowsOpenCodeMachinePolicyInForce = func() bool {
	if !windowsEnterpriseStandaloneProcess() {
		return false
	}
	_, inForce := windowsOpenCodeMachinePolicyState()
	return inForce
}

// windowsStandaloneRuntimeOnlyInstall reports whether a row installs and
// verifies only the per-user runtime: Copilot always, OpenCode while its
// machine policy is in force.
func windowsStandaloneRuntimeOnlyInstall(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if windowsStandaloneRuntimeOnlyConnector(name) {
		return true
	}
	return name == "opencode" && windowsOpenCodeMachinePolicyInForce()
}

// windowsRuntimeOnlyPolicyPath is the vendor machine policy file that
// carries the DefenseClaw hook for a runtime-only connector. The standalone
// guardian publishes it; the per-user row only binds the user runtime to it.
var windowsRuntimeOnlyPolicyPath = func(connectorName string) (string, error) {
	switch connectorName {
	case "copilot":
		programData, err := winpath.TrustedProgramData()
		if err != nil {
			return "", fmt.Errorf("enterprise hooks: resolve trusted ProgramData: %w", err)
		}
		return filepath.Join(programData, "GitHub", "Copilot", "policy.d", "90-defenseclaw.json"), nil
	case "opencode":
		// OpenCode's managed config, which names the managed plugin.
		path, _ := windowsOpenCodeMachinePolicyState()
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
			return "", errors.New("enterprise hooks: the OpenCode machine policy path is not resolved")
		}
		return filepath.Clean(path), nil
	default:
		return "", fmt.Errorf("enterprise hooks: %q has no Windows machine policy runtime", connectorName)
	}
}

// windowsRuntimeOnlyPolicyTrustCheck proves the machine policy file is in
// force: present, administrator-owned and not writable by standard users.
var windowsRuntimeOnlyPolicyTrustCheck = func(path string) error {
	return managed.ValidateTrustedFilePath(path, "Windows machine policy hook file")
}

func windowsRuntimeOnlyPaths(dataDir, connectorName string) []string {
	hookDir := filepath.Join(dataDir, "hooks")
	return []string{
		filepath.Join(hookDir, ".token"),
		filepath.Join(hookDir, ".hookcfg"),
		filepath.Join(hookDir, ".hookcfg."+connectorName),
		filepath.Join(hookDir, ".hookcfg.lock"),
		filepath.Join(hookDir, ".hook-"+connectorName+".token"),
		filepath.Join(dataDir, "hook_contract_lock.json"),
		filepath.Join(dataDir, "hook_contract_lock.json.lock"),
	}
}

func resolveWindowsRuntimeOnlyTarget(opts InstallOptions) (windowsGenericManagedTarget, string, error) {
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return target, "", err
	}
	name := target.conn.Name()
	if !windowsStandaloneRuntimeOnlyInstall(name) {
		return target, "", fmt.Errorf("enterprise hooks: connector %q is not a Windows machine policy runtime connector", name)
	}
	target.setup.HookFailMode = "closed"
	policyPath, err := windowsRuntimeOnlyPolicyPath(name)
	if err != nil {
		return target, "", err
	}
	return target, policyPath, nil
}

// installWindowsRuntimeOnlyManagedResult writes a runtime-only connector's
// per-user DefenseClaw runtime (scoped token, sidecar, hook contract) as the
// target user, prepares its immutable generation, and enrolls the SID. It
// never touches the user's agent configuration.
func installWindowsRuntimeOnlyManagedResult(
	_ context.Context,
	opts InstallOptions,
) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseAgentVersion(opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	target, policyPath, err := resolveWindowsRuntimeOnlyTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	name := target.conn.Name()
	if err := windowsRuntimeOnlyPolicyTrustCheck(policyPath); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: %s machine policy is not in force: %w", name, err)
	}
	transaction := windowsCodexUserRuntimeTransaction{
		home:      target.home,
		dataDir:   target.dataDir,
		hookDir:   filepath.Join(target.dataDir, "hooks"),
		paths:     windowsRuntimeOnlyPaths(target.dataDir, name),
		targetSID: target.sid,
	}
	var lockEntry connector.HookContractLockEntry
	var lockUpdatedAt, entryUpdatedAt string
	var generation WindowsManagedRuntimeGenerationPublication
	if err := ensureWindowsStandaloneHookRuntimeAncestorReadable(); err != nil {
		return InstallResult{}, err
	}
	err = connector.WithUserHomeDir(target.home, func() error {
		return windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
			verifiedHome, verifiedSID, verifyErr := validateWindowsEnterpriseHome(target.home, target.sid.String())
			if verifyErr != nil {
				return verifyErr
			}
			if !sameWindowsEnterprisePath(verifiedHome, target.home) || !verifiedSID.Equals(target.sid) {
				return fmt.Errorf("enterprise hooks: %s target profile identity changed before runtime mutation", name)
			}
			if err := prepareWindowsCodexRuntime(transaction, opts.AllowMissingHookConfigRepair); err != nil {
				return err
			}
			var err error
			transaction.snapshot, err = snapshotWindowsRuntimeFiles(transaction.paths)
			if err != nil {
				return err
			}
			fail := func(cause error) error {
				if transaction.createdDataDir {
					// The selection receipt below is the only file outside
					// the runtime snapshot; a data dir this row created must
					// be empty again for the rollback to remove it.
					removeWindowsManagedSetupSelectionReceipt(target.dataDir)
				}
				if restoreErr := restoreWindowsCodexUserRuntime(transaction); restoreErr != nil {
					return fmt.Errorf("%v (%s runtime rollback failed: %v)", cause, name, restoreErr)
				}
				return cause
			}
			creation, createErr := ensureWindowsTargetOwnedDirectoryTree(transaction.home, transaction.hookDir, transaction.targetSID)
			transaction.createdDataDir = creation.createdDataDir
			transaction.createdHookDir = creation.createdHookDir
			if createErr != nil {
				return fail(fmt.Errorf("enterprise hooks: create %s managed runtime: %w", name, createErr))
			}
			if err := connector.ReconcileManagedNativeHookRuntime(
				target.dataDir, target.setup.APIAddr, name, target.setup.HookAPIToken,
			); err != nil {
				return fail(fmt.Errorf("enterprise hooks: write %s managed runtime: %w", name, err))
			}
			// OpenCode binds its contract publication to protected executable
			// evidence. After the user's own lock is lost (a moved or deleted
			// ~\.defenseclaw) only a fresh guardian receipt can re-establish
			// it, exactly as on the full setup route.
			if err := recordWindowsManagedSetupSelection(target); err != nil {
				return fail(err)
			}
			lockEntry, err = connector.NewHookContractLockEntryForMode(
				target.setup, target.conn, version.Current().BinaryVersion, true,
			)
			if err != nil {
				return fail(fmt.Errorf("enterprise hooks: digest %s managed runtime: %w", name, err))
			}
			lockEntry.HookFailMode = "closed"
			lockEntry.HookScriptDigests = nil
			lockEntry.Locations = connector.ConnectorLocations{HookConfigPaths: []string{policyPath}}
			if err := connector.SaveRecoveredHookContractLockEntryForMode(
				target.dataDir, lockEntry,
				opts.RecoveryHookContractLockUpdatedAt, opts.RecoveryHookContractEntryUpdatedAt,
			); err != nil {
				return fail(fmt.Errorf("enterprise hooks: save %s managed hook contract: %w", name, err))
			}
			lockUpdatedAt, entryUpdatedAt, err = connector.ManagedHookContractTimestamps(target.dataDir, name)
			if err != nil {
				return fail(fmt.Errorf("enterprise hooks: load protected %s hook contract recovery state: %w", name, err))
			}
			if err := hardenWindowsUserRuntime(target.home, target.dataDir, transaction.paths, target.sid); err != nil {
				return fail(err)
			}
			// The VS Code Local harness never reads policy.d: its hooks
			// live in the user's home, written here as the user.
			if err := applyWindowsCopilotVSCodeUser(name, target.home, false, false); err != nil {
				return fail(err)
			}
			if err := verifyWindowsRuntimeOnlyUserRuntime(target, policyPath); err != nil {
				return fail(err)
			}
			generation, _, err = prepareWindowsPerUserManagedGeneration(target, lockEntry.ContractID)
			if err != nil {
				return fail(err)
			}
			return nil
		})
	})
	if err != nil {
		return InstallResult{}, err
	}
	if err := commitWindowsPerUserManagedRegistration(target, generation); err != nil {
		return InstallResult{}, errors.Join(err, windowsEnterpriseTargetImpersonation(
			target.sid, target.home,
			func() error { return restoreWindowsCodexUserRuntime(transaction) },
		))
	}
	return InstallResult{
		Connector:                  name,
		UserHome:                   target.home,
		DataDir:                    target.dataDir,
		HookConfigPaths:            []string{policyPath},
		CreatedDirs:                []string{transaction.dataDir, transaction.hookDir},
		AgentVersion:               target.setup.AgentVersion,
		HookContractID:             lockEntry.ContractID,
		HookContractLockUpdatedAt:  lockUpdatedAt,
		HookContractEntryUpdatedAt: entryUpdatedAt,
	}, nil
}

func verifyWindowsRuntimeOnlyManagedResult(
	_ context.Context,
	opts InstallOptions,
) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseAgentVersion(opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	target, policyPath, err := resolveWindowsRuntimeOnlyTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	name := target.conn.Name()
	if err := windowsRuntimeOnlyPolicyTrustCheck(policyPath); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: %s machine policy is not in force: %w", name, err)
	}
	if err := verifyWindowsRuntimeOnlyUserRuntime(target, policyPath); err != nil {
		return InstallResult{}, err
	}
	lock, err := connector.LoadHookContractLockEntryForMode(target.dataDir, name, true)
	if err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: load %s managed hook contract: %w", name, err)
	}
	if err := verifyWindowsPerUserManagedRegistration(target, lock.ContractID); err != nil {
		return InstallResult{}, err
	}
	// A missing or stale Local hook file or plugin fails verify, so the
	// guardian repairs the row.
	if err := applyWindowsCopilotVSCodeUser(name, target.home, true, false); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{
		Connector:       name,
		UserHome:        target.home,
		DataDir:         target.dataDir,
		HookConfigPaths: []string{policyPath},
		AgentVersion:    lock.RawAgentVersion,
		HookContractID:  lock.ContractID,
	}, nil
}

func verifyWindowsRuntimeOnlyUserRuntime(target windowsGenericManagedTarget, policyPath string) error {
	name := target.conn.Name()
	if err := verifyWindowsUserRuntime(windowsRuntimeOnlyPaths(target.dataDir, name), target.sid); err != nil {
		return err
	}
	if err := connector.ValidateManagedNativeHookRuntime(target.dataDir, target.setup.APIAddr, name); err != nil {
		return fmt.Errorf("enterprise hooks: %s managed runtime is invalid: %w", name, err)
	}
	tokenPath, err := connector.HookTokenFilePath(filepath.Join(target.dataDir, "hooks"), name)
	if err != nil {
		return err
	}
	tokenBody, err := connector.ReadManagedHookRuntimeFile(tokenPath, name+" connector-scoped token", windowsEnterpriseTokenMaxBytes)
	if err != nil {
		return fmt.Errorf("enterprise hooks: read %s connector-scoped token: %w", name, err)
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(tokenBody))), []byte(target.setup.HookAPIToken)) != 1 {
		return fmt.Errorf("enterprise hooks: %s connector-scoped token does not match the protected service token", name)
	}
	lock, err := connector.LoadHookContractLockEntryForMode(target.dataDir, name, true)
	if err != nil {
		return fmt.Errorf("enterprise hooks: load %s managed hook contract: %w", name, err)
	}
	if lock.Connector != name || len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], policyPath) ||
		len(lock.Locations.HookScriptPaths) != 0 ||
		!strings.EqualFold(strings.TrimSpace(lock.HookFailMode), "closed") {
		return fmt.Errorf("enterprise hooks: %s managed hook contract does not identify only its machine policy", name)
	}
	return nil
}

// removeWindowsRuntimeOnlyManagedRuntime revokes the SID and clears its hook
// contract. The machine policy file stays: it serves every enrolled user.
// DefenseClaw's own user-level registration for the connector (Copilot's
// ~/.copilot/hooks/defenseclaw.json, written by an earlier per-user setup)
// is removed as the user; the user's own hooks stay.
func removeWindowsRuntimeOnlyManagedRuntime(ctx context.Context, opts InstallOptions, conn connector.Connector) error {
	connectorName := conn.Name()
	targetSID, err := validateWindowsEnterpriseTargetSID(opts.OwnerSID)
	if err != nil {
		return err
	}
	home, verifiedSID, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return err
	}
	if !verifiedSID.Equals(targetSID) {
		return errors.New("enterprise hooks: target profile SID changed before managed revocation")
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return err
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return err
	}
	hookExecutable = filepath.Clean(hookExecutable)
	if err := revokeWindowsPerUserManagedRegistration(connectorName, targetSID, dataDir, hookExecutable); err != nil {
		return err
	}
	return windowsEnterpriseTargetImpersonation(targetSID, home, func() error {
		if err := removeWindowsRuntimeOnlyUserRegistration(ctx, conn, home, dataDir, hookExecutable, targetSID); err != nil {
			return err
		}
		if err := applyWindowsCopilotVSCodeUser(connectorName, home, false, true); err != nil {
			return err
		}
		if _, statErr := os.Lstat(dataDir); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if err := connector.ClearHookContractLockEntryForMode(dataDir, connectorName, true); err != nil {
			return fmt.Errorf("enterprise hooks: clear connector %s hook contract lock: %w", connectorName, err)
		}
		return nil
	})
}

// removeWindowsRuntimeOnlyUserRegistration runs the connector's teardown,
// under the caller's target impersonation, only when a DefenseClaw-owned
// user-level hook file exists inside the user's home. Teardown removes
// DefenseClaw's entries and keeps every other handler; a user without the
// file gets nothing written.
func removeWindowsRuntimeOnlyUserRegistration(
	ctx context.Context,
	conn connector.Connector,
	home, dataDir, hookExecutable string,
	targetSID *windows.SID,
) error {
	setup := connector.SetupOpts{
		DataDir:           dataDir,
		ManagedEnterprise: true,
		HookExecutable:    hookExecutable,
	}
	if err := validateWindowsEnterpriseImpersonationSetup(setup); err != nil {
		return err
	}
	return connector.WithUserHomeDir(home, func() error {
		present := false
		for _, path := range connector.HookConfigPathsForConnector(conn, setup) {
			path = filepath.Clean(strings.TrimSpace(path))
			if !filepath.IsAbs(path) || !pathInside(home, path) {
				continue
			}
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return fmt.Errorf("enterprise hooks: inspect %s user hook file %s: %w", conn.Name(), path, err)
			}
			if err := prepareWindowsGenericPath(home, path, targetSID, false, false, false, "removal file"); err != nil {
				return err
			}
			present = true
		}
		if !present {
			return nil
		}
		if err := conn.Teardown(ctx, setup); err != nil {
			return fmt.Errorf(
				"enterprise hooks: connector %s user hook teardown failed under target SID %s: %w",
				conn.Name(),
				targetSID,
				err,
			)
		}
		return nil
	})
}
