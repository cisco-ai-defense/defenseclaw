//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var enterpriseHookWindowsRegistrationVerifier = enterprisehooks.VerifyWindowsManagedRegistration

// The guardian publishes readiness for hooks it actually installed. The
// lifecycle's separate coverage report still refuses to certify a Hermes
// home selected only by a later user session.
func enterpriseHookGuardianVerify(ctx context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
	if strings.EqualFold(strings.TrimSpace(opts.ConnectorName), "hermes") &&
		cfg != nil && cfg.StandaloneEnterprise() && !cfg.SecureClientIntegration() {
		return enterpriseHookWindowsRegistrationVerifier(ctx, opts)
	}
	return enterprisehooks.Verify(ctx, opts)
}

var enterpriseHookSIDProfilePath = windowsEnterpriseHookSIDProfilePath

var enterpriseHookWindowsSystemDirectory = windows.GetSystemDirectory

var enterpriseHookWindowsTargetSessionCheck = enterprisehooks.RequireWindowsEnterpriseTargetSession
var enterpriseHookWindowsDeferredPendingCheck = enterprisehooks.RequireWindowsEnterpriseDeferredTargetPending
var enterpriseHookClaudePolicyIdentityVerifier = enterprisehooks.VerifyWindowsClaudeManagedPolicyIdentity
var enterpriseHookCursorPolicyIdentityVerifier = enterprisehooks.VerifyWindowsCursorManagedPolicyIdentity
var enterpriseHookClaudePolicyTargetsReader = enterprisehooks.ReadWindowsClaudeManagedPolicyTargets
var enterpriseHookClaudePolicyTargetsPublisher = enterprisehooks.PublishWindowsClaudeManagedPolicyTargets
var enterpriseHookCursorPolicyTargetsReader = enterprisehooks.ReadWindowsCursorManagedPolicyTargets
var enterpriseHookCursorPolicyTargetsPublisher = enterprisehooks.PublishWindowsCursorManagedPolicyTargets
var enterpriseHookCodexRequirementsLayoutResolver = resolveWindowsCodexRequirementsLayout
var enterpriseHookCodexRuntimeRegistryReader = connector.ResolveWindowsCodexManagedRuntimeRegistry
var enterpriseHookCodexRequirementsRemover = connector.RemoveWindowsCodexMachineRequirements
var enterpriseHookCodexRequirementsReconciler = connector.ReconcileWindowsCodexMachineRequirements
var enterpriseHookCodexTargetsPublisher = connector.PublishWindowsCodexManagedRuntimeTargets
var enterpriseHookClaudePolicyEnsurer = enterprisehooks.EnsureWindowsStandaloneClaudeManagedPolicy
var enterpriseHookClaudePolicyRestorer = enterprisehooks.RestoreWindowsClaudeManagedPolicyDrift
var enterpriseHookClaudePolicyDeactivator = enterprisehooks.DeactivateWindowsClaudeManagedPolicy
var enterpriseHookCursorPolicyEnsurer = enterprisehooks.EnsureWindowsStandaloneCursorManagedPolicy
var enterpriseHookCursorPolicyRestorer = enterprisehooks.RestoreWindowsCursorManagedAdapter
var enterpriseHookCursorPolicyDeactivator = enterprisehooks.DeactivateWindowsCursorManagedPolicy

// enterpriseHookRemovedAccountNote follows each failure status and verify
// report as a warning for a deleted account whose profile folder was removed.
const enterpriseHookRemovedAccountNote = " (the account was deleted and its profile folder removed; the enumerator drops its rows at its next pass)"

// enterpriseHookRemovedAccountRow reports, on a standalone deployment only,
// a guardian row of a local account that was deleted: no one can sign in as
// it, and the enumerator drops its rows at its next pass, also when its
// profile folder could not be removed (GAP-0430). Tests replace it.
var enterpriseHookRemovedAccountRow = func(row enterpriseHookReconcileRow) bool {
	if cfg == nil || !cfg.StandaloneEnterprise() || strings.TrimSpace(row.UserHome) == "" {
		return false
	}
	return windowsEnterpriseAccountDeleted(row.SID)
}

// enterpriseHookSignedOutAccount names, on a standalone deployment only, the
// account of a guardian row that failed only because the account is signed
// out ("user (SID)"), or returns "" for any other row. Tests replace it.
var enterpriseHookSignedOutAccount = func(row enterpriseHookReconcileRow) string {
	if cfg == nil || !cfg.StandaloneEnterprise() || !enterpriseHookSessionUnavailable(row.Error) ||
		enterpriseHookRemovedAccountRow(row) {
		return ""
	}
	return enterpriseHookWindowsAccountLabel(row)
}

// enterpriseHookWindowsAccountLabel is "user (SID)", looking the account up
// when the row carries only its SID.
func enterpriseHookWindowsAccountLabel(row enterpriseHookReconcileRow) string {
	user, sid := strings.TrimSpace(row.User), strings.TrimSpace(row.SID)
	if user == "" && sid != "" {
		if parsed, err := windows.StringToSid(sid); err == nil {
			if account, domain, _, err := parsed.LookupAccount(""); err == nil {
				user = account
				if domain != "" {
					user = domain + `\` + account
				}
			}
		}
	}
	switch {
	case user == "":
		return sid
	case sid == "":
		return user
	}
	return user + " (" + sid + ")"
}

// enterpriseHookManifestCatchUpAllowed reports a standalone deployment,
// whose status waits for the guardian to activate a targets.yaml the
// enumerator just republished (enterpriseHookManifestActivationIssue).
// Tests replace it.
var enterpriseHookManifestCatchUpAllowed = func() bool {
	return cfg != nil && cfg.StandaloneEnterprise()
}

func enterpriseHookTargetSessionAvailable(
	target enterprisehooks.ManifestTarget,
) (bool, error) {
	err := enterpriseHookWindowsTargetSessionCheck(
		strings.TrimSpace(target.SID),
		strings.TrimSpace(target.UserHome),
	)
	if err == nil {
		return true, nil
	}
	if enterprisehooks.IsWindowsTargetSessionUnavailable(err) {
		return false, nil
	}
	return false, err
}

// enterpriseHookTargetClosingLogon is enterpriseHookReconcileClosingLogon.
func enterpriseHookTargetClosingLogon(target enterprisehooks.ManifestTarget) error {
	return enterprisehooks.RequireWindowsEnterpriseTargetLogon(
		strings.TrimSpace(target.SID),
		strings.TrimSpace(target.UserHome),
		enterprisehooks.WindowsTargetLogonAnyWithS4U,
	)
}

func enterpriseHookDeferredTargetSessionAvailable(
	target enterprisehooks.ManifestTarget,
) (bool, error) {
	available, err := enterpriseHookTargetSessionAvailable(target)
	if err != nil || available {
		return available, err
	}
	if pendingErr := enterpriseHookWindowsDeferredPendingCheck(target); pendingErr != nil {
		return false, pendingErr
	}
	return false, nil
}

// enterpriseHookMachinePolicyContract returns the hook contract a standalone
// deployment renders its single machine-wide Claude policy from, so every
// Claude row installs, repairs and verifies one body. Secure Client renders
// each row's own contract.
func enterpriseHookMachinePolicyContract(manifest enterprisehooks.Manifest) string {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return ""
	}
	return enterprisehooks.WindowsStandaloneClaudeMachinePolicyContract(manifest)
}

// enterpriseHookStandaloneManifestPath is the standalone guardian's
// targets.yaml, the manifest the deployment-wide Claude contract comes from.
var enterpriseHookStandaloneManifestPath = func() (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", err
	}
	return layout.ManifestPath, nil
}

// enterpriseHookInstallMachinePolicyContract returns the deployment-wide
// Claude machine-policy contract for a single-target administrator install.
// Without it the install would render the shared body from this row's own
// contract and the guardian's next reconcile would rewrite it back. A
// standalone host whose guardian has not published targets.yaml yet has no
// deployment contract, so the row's own is used; a manifest that exists but
// is untrusted or unreadable refuses the install.
func enterpriseHookInstallMachinePolicyContract(connectorName string) (string, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() ||
		!strings.EqualFold(strings.TrimSpace(connectorName), "claudecode") {
		return "", nil
	}
	path, err := enterpriseHookStandaloneManifestPath()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks install: resolve the guardian manifest: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err := enterpriseHookManifestFileTrustCheck(path); err != nil {
		return "", fmt.Errorf("enterprise hooks install: guardian manifest trust check failed: %w", err)
	}
	manifest, err := enterprisehooks.LoadManifest(path)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks install: load the guardian manifest for the machine-wide Claude contract: %w", err)
	}
	return enterpriseHookMachinePolicyContract(manifest), nil
}

func stageEnterpriseHookDeferredManagedPolicies(
	manifest enterprisehooks.Manifest,
	pending []enterprisehooks.ManifestTarget,
	apiAddr string,
) error {
	return enterprisehooks.StageWindowsEnterpriseDeferredPolicies(
		manifest,
		pending,
		apiAddr,
		cfg.EffectiveHookFailModeForConnector("cursor"),
	)
}

func syncEnterpriseHookManagedEnrollments(
	manifest enterprisehooks.Manifest,
	apiAddr string,
	publishExact bool,
) error {
	if cfg != nil && (cfg.StandaloneEnterprise() || cfg.SecureClientIntegration()) {
		// Per-user connectors (Copilot alone on Secure Client) carry their
		// own machine enrollment; revoke SIDs the manifest no longer
		// authorizes first so they fail closed even when a later step fails.
		codexOpts, err := resolveWindowsCodexRequirementsLayout("reconcile")
		if err != nil {
			return err
		}
		if err := pruneWindowsStandalonePerUserEnrollments(manifest, codexOpts.HookBinary); err != nil {
			return err
		}
	}
	return syncEnterpriseHookManagedMachineEnrollments(manifest, apiAddr, publishExact)
}

func syncEnterpriseHookManagedMachineEnrollments(
	manifest enterprisehooks.Manifest,
	apiAddr string,
	publishExact bool,
) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	configured := windowsEnterpriseConfiguredMachinePolicies()
	desiredClaude, desiredCodex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		return err
	}
	desiredCursor, err := windowsEnterpriseDesiredCursorEnrollments(manifest)
	if err != nil {
		return err
	}
	codexOpts, err := enterpriseHookCodexRequirementsLayoutResolver("reconcile")
	if err != nil {
		return err
	}
	currentClaude, claudeActive, err := enterpriseHookClaudePolicyTargetsReader()
	var claudeRestoreErr error
	if err != nil && cfg.StandaloneEnterprise() && configured["claudecode"] {
		// The ownership record can outlive a changed or deleted drop-in. Put
		// the drop-in back from that record, then read its enrollment before
		// pre-sync can publish a smaller target set. The ensure below still
		// tries an unrestored guard and reports both failures.
		restored, restoreErr := enterpriseHookClaudePolicyRestorer()
		claudeRestoreErr = restoreErr
		if restoreErr == nil && restored {
			currentClaude, claudeActive, err = enterpriseHookClaudePolicyTargetsReader()
		}
	}
	if err != nil {
		if (!cfg.StandaloneEnterprise() || !configured["claudecode"]) &&
			(publishExact || len(desiredClaude) == 0) {
			return err
		}
		// The active global command remains fail-closed while protected state
		// is incomplete. Let the narrow per-target secure Install path attempt
		// its ownership-bound repair; final exact publication below will still
		// reject any unrepaired damage.
		currentClaude = nil
		claudeActive = false
	}
	if cfg.StandaloneEnterprise() {
		switch {
		case configured["claudecode"] && !claudeActive:
			if err := enterpriseHookClaudePolicyEnsurer(connector.SetupOpts{
				APIAddr: apiAddr, HookExecutable: codexOpts.HookBinary,
				HookContractID: enterpriseHookMachinePolicyContract(manifest),
			}); err != nil {
				return fmt.Errorf("ensure configured Claude machine policy: %w", errors.Join(claudeRestoreErr, err))
			}
			currentClaude, claudeActive, err = enterpriseHookClaudePolicyTargetsReader()
			if err != nil {
				return fmt.Errorf("read ensured Claude machine policy: %w", err)
			}
			if !claudeActive {
				return errors.New("configured Claude machine policy did not become active")
			}
		case !configured["claudecode"] && claudeActive:
			if err := enterpriseHookClaudePolicyDeactivator(); err != nil {
				return fmt.Errorf("deactivate removed Claude connector: %w", err)
			}
			currentClaude = nil
			claudeActive = false
		}
	}
	if publishExact {
		if claudeActive || len(desiredClaude) > 0 {
			if err := enterpriseHookClaudePolicyTargetsPublisher(desiredClaude); err != nil {
				return err
			}
		}
	} else if claudeActive {
		desired := make(map[string]struct{}, len(desiredClaude))
		for _, sid := range desiredClaude {
			desired[sid] = struct{}{}
		}
		retained := make([]string, 0, len(currentClaude))
		for _, sid := range currentClaude {
			if _, ok := desired[sid]; ok {
				retained = append(retained, sid)
			}
		}
		if err := enterpriseHookClaudePolicyTargetsPublisher(retained); err != nil {
			return err
		}
	}

	currentCodex, err := enterpriseHookCodexRuntimeRegistryReader(
		codexOpts.HookBinary,
	)
	var deferredCodexErr error
	if cfg.StandaloneEnterprise() && configured["codex"] && (err != nil || !currentCodex.Active) {
		codexOpts.CodexTargetEnabled = true
		report, reconcileErr := enterpriseHookCodexRequirementsReconciler(codexOpts)
		if reconcileErr != nil {
			return fmt.Errorf("ensure configured Codex machine requirements: %w", reconcileErr)
		}
		if !report.OK {
			return errors.New("configured Codex machine requirements were not published")
		}
		currentCodex, err = enterpriseHookCodexRuntimeRegistryReader(codexOpts.HookBinary)
		if err == nil && !currentCodex.Active {
			return errors.New("configured Codex machine requirements did not become active")
		}
	}
	if err != nil {
		if publishExact || len(desiredCodex) == 0 {
			deferredCodexErr = err
		}
		// As above, defer only to the trusted machine-policy reconciler. The
		// target stays unregistered/fail-closed until final exact publication,
		// but still revoke an independent stale Cursor enrollment below.
	} else if len(desiredCodex) == 0 && (!cfg.StandaloneEnterprise() || !configured["codex"]) {
		if currentCodex.Active {
			report, err := enterpriseHookCodexRequirementsRemover(codexOpts)
			if err != nil {
				return err
			}
			if !report.OK || !report.SafeToRemoveBinary ||
				report.SurvivingOwnedPathReferences != 0 {
				return fmt.Errorf("Codex machine requirements removal was not reference-clean")
			}
		}
	} else if publishExact {
		if !currentCodex.Active {
			return fmt.Errorf("Codex managed policy is absent after target runtime installation")
		}
		if err := enterpriseHookCodexTargetsPublisher(codexOpts, desiredCodex); err != nil {
			return err
		}
	} else if currentCodex.Active {
		desired := make(map[string]string, len(desiredCodex))
		for _, target := range desiredCodex {
			desired[strings.ToUpper(target.SID)] = target.DataDir
		}
		retained := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(currentCodex.Targets))
		for _, target := range currentCodex.Targets {
			dataDir, ok := desired[strings.ToUpper(target.SID)]
			if ok && sameWindowsEnterprisePathCLI(dataDir, target.DataDir) {
				retained = append(retained, target)
			}
		}
		if err := enterpriseHookCodexTargetsPublisher(codexOpts, retained); err != nil {
			return err
		}
	}

	currentCursor, cursorActive, err := enterpriseHookCursorPolicyTargetsReader()
	if err != nil && cfg.StandaloneEnterprise() && configured["cursor"] {
		// The protected state can outlive a deleted or changed adapter or
		// hooks.json. Rebuild both from that state, then read its enrollment
		// before pre-sync can publish a smaller target set.
		restored, restoreErr := enterpriseHookCursorPolicyRestorer(codexOpts.HookBinary)
		if restoreErr != nil {
			return fmt.Errorf("restore configured Cursor machine policy: %w", errors.Join(err, restoreErr))
		}
		if restored {
			currentCursor, cursorActive, err = enterpriseHookCursorPolicyTargetsReader()
		}
	}
	if err != nil {
		if (!cfg.StandaloneEnterprise() || !configured["cursor"]) &&
			(publishExact || len(desiredCursor) == 0) {
			return err
		}
		currentCursor = nil
		cursorActive = false
	}
	if cfg.StandaloneEnterprise() {
		switch {
		case configured["cursor"] && !cursorActive:
			if err := enterpriseHookCursorPolicyEnsurer(connector.SetupOpts{
				APIAddr: apiAddr, HookExecutable: codexOpts.HookBinary,
			}); err != nil {
				return fmt.Errorf("ensure configured Cursor machine policy: %w", err)
			}
			currentCursor, cursorActive, err = enterpriseHookCursorPolicyTargetsReader()
			if err != nil {
				return fmt.Errorf("read ensured Cursor machine policy: %w", err)
			}
			if !cursorActive {
				return errors.New("configured Cursor machine policy did not become active")
			}
		case !configured["cursor"] && cursorActive:
			if err := enterpriseHookCursorPolicyDeactivator(); err != nil {
				return fmt.Errorf("deactivate removed Cursor connector: %w", err)
			}
			currentCursor = nil
			cursorActive = false
		}
	}
	if publishExact {
		if len(desiredCursor) > 0 && !cursorActive {
			return fmt.Errorf("Cursor enterprise policy is absent after target runtime installation")
		}
		if cursorActive || len(desiredCursor) == 0 {
			if err := enterpriseHookCursorPolicyTargetsPublisher(desiredCursor); err != nil {
				return err
			}
		}
		return deferredCodexErr
	}
	if !cursorActive {
		return deferredCodexErr
	}
	desiredCursorBySID := make(map[string]string, len(desiredCursor))
	for _, target := range desiredCursor {
		desiredCursorBySID[strings.ToUpper(target.SID)] = target.DataDir
	}
	retainedCursor := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(currentCursor))
	for _, target := range currentCursor {
		dataDir, ok := desiredCursorBySID[strings.ToUpper(target.SID)]
		if ok && sameWindowsEnterprisePathCLI(dataDir, target.DataDir) {
			retainedCursor = append(retainedCursor, target)
		}
	}
	if err := enterpriseHookCursorPolicyTargetsPublisher(retainedCursor); err != nil {
		return err
	}
	return deferredCodexErr
}

func windowsEnterpriseDesiredCursorEnrollments(
	manifest enterprisehooks.Manifest,
) ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, error) {
	desired := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if !target.IsEnabled() || !strings.EqualFold(strings.TrimSpace(target.Connector), "cursor") {
			continue
		}
		resolved, err := resolveEnterpriseHookTargetValues(
			target.User,
			target.UserHome,
			intPtrValue(target.UID),
			intPtrValue(target.GID),
			target.SID,
			target.DataDir,
		)
		if err != nil {
			return nil, err
		}
		sid, err := windows.StringToSid(strings.TrimSpace(resolved.sid))
		if err != nil || sid == nil {
			return nil, fmt.Errorf("invalid Windows Cursor enrollment SID %q", resolved.sid)
		}
		dataDir := filepath.Join(filepath.Clean(resolved.home), ".defenseclaw")
		if configured := strings.TrimSpace(target.DataDir); configured != "" {
			configured, err = filepath.Abs(configured)
			if err != nil {
				return nil, err
			}
			configured = filepath.Clean(configured)
			if !sameWindowsEnterprisePathCLI(configured, dataDir) {
				return nil, fmt.Errorf("Cursor target %s data_dir does not equal canonical %s", sid, dataDir)
			}
		}
		desired = append(desired, enterprisehooks.WindowsCursorManagedRuntimeTarget{
			SID: sid.String(), DataDir: dataDir,
		})
	}
	sort.Slice(desired, func(i, j int) bool { return desired[i].SID < desired[j].SID })
	return desired, nil
}

func windowsEnterpriseDesiredEnrollments(
	manifest enterprisehooks.Manifest,
) ([]string, []connector.WindowsCodexManagedRuntimeTarget, error) {
	desiredClaude := make([]string, 0, len(manifest.Targets))
	desiredCodex := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		resolved, err := resolveEnterpriseHookTargetValues(
			target.User,
			target.UserHome,
			intPtrValue(target.UID),
			intPtrValue(target.GID),
			target.SID,
			target.DataDir,
		)
		if err != nil {
			return nil, nil, err
		}
		sid, err := windows.StringToSid(strings.TrimSpace(resolved.sid))
		if err != nil || sid == nil {
			return nil, nil, fmt.Errorf("invalid Windows enrollment SID %q", resolved.sid)
		}
		switch strings.ToLower(strings.TrimSpace(target.Connector)) {
		case "claudecode":
			desiredClaude = append(desiredClaude, sid.String())
		case "codex":
			dataDir := filepath.Join(filepath.Clean(resolved.home), ".defenseclaw")
			if configured := strings.TrimSpace(target.DataDir); configured != "" {
				configured, err = filepath.Abs(configured)
				if err != nil {
					return nil, nil, err
				}
				configured = filepath.Clean(configured)
				if !sameWindowsEnterprisePathCLI(configured, dataDir) {
					return nil, nil, fmt.Errorf(
						"Codex target %s data_dir does not equal canonical %s",
						sid,
						dataDir,
					)
				}
			}
			desiredCodex = append(desiredCodex, connector.WindowsCodexManagedRuntimeTarget{
				SID:     sid.String(),
				DataDir: dataDir,
			})
		}
	}
	sort.Strings(desiredClaude)
	sort.Slice(desiredCodex, func(i, j int) bool {
		return desiredCodex[i].SID < desiredCodex[j].SID
	})
	return desiredClaude, desiredCodex, nil
}

func verifyEnterpriseHookManagedEnrollments(
	manifest enterprisehooks.Manifest,
	_ string,
) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	desiredClaude, desiredCodex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		return err
	}
	desiredCursor, err := windowsEnterpriseDesiredCursorEnrollments(manifest)
	if err != nil {
		return err
	}
	currentClaude, claudeActive, err := enterpriseHookClaudePolicyTargetsReader()
	if err != nil {
		return err
	}
	expected := windowsEnterpriseConfiguredMachinePolicies()
	if claudeActive != (expected["claudecode"] || len(desiredClaude) > 0) ||
		!equalWindowsEnterpriseStringSet(currentClaude, desiredClaude) {
		return fmt.Errorf("Claude protected SID enrollment does not match the enabled manifest")
	}

	codexOpts, err := enterpriseHookCodexRequirementsLayoutResolver("verify")
	if err != nil {
		return err
	}
	currentCodex, err := enterpriseHookCodexRuntimeRegistryReader(
		codexOpts.HookBinary,
	)
	if err != nil {
		return err
	}
	if currentCodex.Active != (expected["codex"] || len(desiredCodex) > 0) ||
		len(currentCodex.Targets) != len(desiredCodex) {
		return fmt.Errorf("Codex protected SID enrollment does not match the enabled manifest")
	}
	for index := range desiredCodex {
		if !strings.EqualFold(currentCodex.Targets[index].SID, desiredCodex[index].SID) ||
			!sameWindowsEnterprisePathCLI(
				currentCodex.Targets[index].DataDir,
				desiredCodex[index].DataDir,
			) {
			return fmt.Errorf("Codex protected SID enrollment does not match the enabled manifest")
		}
	}
	currentCursor, cursorActive, err := enterpriseHookCursorPolicyTargetsReader()
	if err != nil {
		return err
	}
	if cursorActive != (expected["cursor"] || len(desiredCursor) > 0) || len(currentCursor) != len(desiredCursor) {
		return fmt.Errorf("Cursor protected SID enrollment does not match the enabled manifest")
	}
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		codexOpts,
		claudeActive,
		currentCodex,
		cursorActive,
	); err != nil {
		return err
	}
	for index := range desiredCursor {
		if !strings.EqualFold(currentCursor[index].SID, desiredCursor[index].SID) ||
			!sameWindowsEnterprisePathCLI(currentCursor[index].DataDir, desiredCursor[index].DataDir) {
			return fmt.Errorf("Cursor protected SID enrollment does not match the enabled manifest")
		}
	}
	return nil
}

func windowsEnterpriseConfiguredMachinePolicies() map[string]bool {
	configured := map[string]bool{}
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return configured
	}
	for _, name := range enterprisehooks.EffectiveWindowsStandaloneHookConnectors(cfg) {
		switch name {
		case "claudecode", "codex", "cursor":
			configured[name] = true
		}
	}
	return configured
}

func verifyWindowsEnterpriseManagedPolicyIdentities(
	codexOpts connector.WindowsCodexMachineRequirementsOptions,
	claudeActive bool,
	currentCodex connector.WindowsCodexManagedRuntimeRegistry,
	cursorActive bool,
) error {
	if claudeActive {
		if err := enterpriseHookClaudePolicyIdentityVerifier(
			codexOpts.HookBinary,
			codexOpts.GatewayAddr,
			codexOpts.GatewayServiceName,
		); err != nil {
			return err
		}
	}
	if currentCodex.Active && (currentCodex.GatewayAddr != codexOpts.GatewayAddr ||
		currentCodex.GatewayServiceName != codexOpts.GatewayServiceName) {
		return fmt.Errorf("Codex protected machine identity does not match the gateway deployment")
	}
	if cursorActive {
		if err := enterpriseHookCursorPolicyIdentityVerifier(
			codexOpts.HookBinary,
			codexOpts.GatewayAddr,
			codexOpts.GatewayServiceName,
		); err != nil {
			return err
		}
	}
	return nil
}

func equalWindowsEnterpriseStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) {
	// The guardian must never promote service-writable runtime state into its
	// administrator-owned configuration. In particular this intentionally
	// skips rootPersistentPreRunE's runtime .env load and runtime migration.
	return config.LoadFromFile(config.ConfigPath())
}

// refuseEnterpriseIdentityViewForStandardUser is a no-op on Windows: the
// views run from an elevated prompt, and the gateway refuses others.
func refuseEnterpriseIdentityViewForStandardUser(*cobra.Command) error { return nil }

func enterpriseHooksNativePersistentPreRun(cmd *cobra.Command, args []string) error {
	if enterpriseHooksRuntimeGOOS() != "windows" {
		if cmd == enterpriseHooksStatusCmd {
			return enterpriseHooksConfigOnlyPersistentPreRun(cmd, args)
		}
		return enterpriseHooksFullRootPersistentPreRun(cmd, args)
	}
	if versionJSON {
		return nil
	}
	// The administrator-installed SCM deployment-mode pin is the trust-safe
	// mode probe. Outside that explicitly enabled mode, delegate immediately
	// so normal Windows startup retains its historical dotenv/config order and
	// performs no preliminary protected-config I/O.
	if !managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		if cmd == enterpriseHooksStatusCmd {
			return enterpriseHooksConfigOnlyPersistentPreRun(cmd, args)
		}
		return enterpriseHooksFullRootPersistentPreRun(cmd, args)
	}
	loaded, err := enterpriseHooksWindowsConfigLoader()
	if err != nil {
		return fmt.Errorf(
			"failed to load protected enterprise config (the guardian ignores runtime .env and requires administrator-provisioned configuration and non-secret service pins): %w",
			err,
		)
	}
	if !managed.IsManagedEnterprise(loaded.DeploymentMode) {
		return fmt.Errorf(
			"failed to load protected enterprise config: immutable %s enables managed enterprise mode but the protected config resolved deployment_mode=%q",
			managed.DeploymentModeEnv,
			loaded.DeploymentMode,
		)
	}
	if err := adoptWindowsEnterpriseProfilePin(loaded); err != nil {
		return err
	}
	cfg = loaded
	version.SetBinaryVersion(appVersion)
	return nil
}

// adoptWindowsEnterpriseProfilePin gives this process the standalone profile
// pin when the protected config it loaded resolves the standalone profile.
// The enterprisehooks renderer, its version gates and its delivery contract
// read the process pin; an unpinned LocalSystem or administrator run against
// a standalone install (no DEFENSECLAW_ENTERPRISE_PROFILE in its
// environment) otherwise took the Secure Client path: the best-effort
// contract, open delivery for unset or unversioned agents, no agent-version
// gate (GAP-0013). The resolved profile of the install decides, as the Unix
// guardian's configureEnterpriseHooksStandaloneUnix does; a Secure Client
// install never gets the pin, and a pin that contradicts the config already
// failed the load.
func adoptWindowsEnterpriseProfilePin(loaded *config.Config) error {
	if loaded == nil || !loaded.StandaloneEnterprise() ||
		managed.IsStandaloneProfile(os.Getenv(managed.EnterpriseProfileEnv)) {
		return nil
	}
	if err := os.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone); err != nil {
		return fmt.Errorf("pin the standalone enterprise profile for this process: %w", err)
	}
	return nil
}

func enterpriseHooksNativePlatformPreflight() error {
	if enterpriseHooksRuntimeGOOS() != "windows" {
		return nil
	}
	if managed.WindowsCurrentProcessIsGatewayService() {
		return fmt.Errorf("enterprise hooks cannot run inside the managed gateway service")
	}
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return fmt.Errorf("enterprise hooks require an elevated administrator or LocalSystem token on native Windows")
}

func windowsEnterpriseHookSIDProfilePath(rawSID string) (string, error) {
	sid, err := windows.StringToSid(strings.TrimSpace(rawSID))
	if err != nil {
		return "", fmt.Errorf("parse SID: %w", err)
	}
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid.String(),
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", err
	}
	defer key.Close()
	profile, valueType, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", err
	}
	if valueType == registry.EXPAND_SZ {
		profile, err = expandEnterpriseHookProfileImagePath(profile)
		if err != nil {
			return "", err
		}
	}
	profile = strings.TrimSpace(profile)
	if profile == "" || !filepath.IsAbs(profile) {
		return "", fmt.Errorf("profile path is empty or not absolute")
	}
	return filepath.Clean(profile), nil
}

func expandEnterpriseHookProfileImagePath(profile string) (string, error) {
	const systemDrive = `%SystemDrive%`
	profile = strings.TrimSpace(profile)
	if len(profile) < len(systemDrive) || !strings.EqualFold(profile[:len(systemDrive)], systemDrive) {
		if strings.Contains(profile, "%") {
			return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
		}
		return profile, nil
	}
	systemDirectory, err := enterpriseHookWindowsSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve trusted Windows system drive: %w", err)
	}
	drive := filepath.VolumeName(filepath.Clean(systemDirectory))
	if drive == "" {
		return "", fmt.Errorf("resolve trusted Windows system drive from %q", systemDirectory)
	}
	expanded := drive + profile[len(systemDrive):]
	if strings.Contains(expanded, "%") {
		return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
	}
	return expanded, nil
}

func enterpriseHooksNativeMutationIdentityPreflight() error {
	if enterpriseHooksRuntimeGOOS() != "windows" {
		return nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("managed enterprise hook mutations require LocalSystem on native Windows: inspect process identity: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("managed enterprise hook mutations require the LocalSystem guardian on native Windows")
	}
	if managed.WindowsCurrentProcessIsGatewayService() {
		return fmt.Errorf("managed enterprise hook mutations cannot run inside the managed gateway service")
	}
	return nil
}
