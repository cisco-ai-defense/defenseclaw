// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

const (
	windowsManagedHooksTeardownSchema      = 1
	windowsManagedHooksTeardownJournalMax  = 4 << 20
	windowsManagedHooksTeardownJournalFile = "managed-hooks-teardown-journal.json"
)

type windowsManagedHooksTeardownTarget struct {
	Connector    string `json:"connector"`
	SID          string `json:"sid"`
	DataDir      string `json:"data_dir"`
	AgentVersion string `json:"agent_version"`
}

type windowsManagedHooksTeardownJournal struct {
	SchemaVersion       int                                                        `json:"schema_version"`
	Phase               string                                                     `json:"phase"`
	ManifestPath        string                                                     `json:"manifest_path"`
	ManifestFingerprint string                                                     `json:"manifest_fingerprint"`
	HookBinary          string                                                     `json:"hook_binary"`
	GatewayAddr         string                                                     `json:"gateway_addr"`
	GatewayServiceName  string                                                     `json:"gateway_service_name"`
	Targets             []windowsManagedHooksTeardownTarget                        `json:"targets"`
	Claude              enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot `json:"claude"`
}

type windowsManagedHooksTeardownResult struct {
	Connector string `json:"connector"`
	SID       string `json:"sid"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

type windowsManagedHooksTeardownReport struct {
	SchemaVersion                int                                 `json:"schema_version"`
	Action                       string                              `json:"action"`
	OK                           bool                                `json:"ok"`
	ManifestPath                 string                              `json:"manifest_path"`
	JournalPath                  string                              `json:"journal_path"`
	TargetCount                  int                                 `json:"target_count"`
	SucceededCount               int                                 `json:"succeeded_count"`
	VerifiedCleanCount           int                                 `json:"verified_clean_count"`
	VerifiedInstalledCount       int                                 `json:"verified_installed_count"`
	FailedCount                  int                                 `json:"failed_count"`
	SurvivingOwnedPathReferences int                                 `json:"surviving_owned_path_references"`
	RollbackReady                bool                                `json:"rollback_ready"`
	SafeToRemoveBinary           bool                                `json:"safe_to_remove_binary"`
	RollbackCompleted            bool                                `json:"rollback_completed"`
	Results                      []windowsManagedHooksTeardownResult `json:"results"`
	Error                        string                              `json:"error,omitempty"`
}

func newWindowsManagedHooksTeardownCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "teardown-managed-hooks",
		Short:  "Transactionally revoke managed hook machine wiring",
		Hidden: true,
	}
	for _, action := range []string{"prepare", "verify", "rollback"} {
		action := action
		var jsonOutput bool
		child := &cobra.Command{
			Use:          action,
			Short:        action + " managed hook machine-wiring teardown",
			Hidden:       true,
			Args:         cobra.NoArgs,
			SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) error {
				report, err := runWindowsManagedHooksTeardown(action)
				if jsonOutput {
					if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); encodeErr != nil {
						if err == nil {
							return encodeErr
						}
						return fmt.Errorf(
							"managed-hook teardown %s failed and its JSON report could not be encoded",
							action,
						)
					}
				} else if err == nil {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"Windows managed-hook teardown %s: targets=%d, succeeded=%d\n",
						action,
						report.TargetCount,
						report.SucceededCount,
					)
				}
				if err != nil {
					return fmt.Errorf("managed-hook teardown %s failed", action)
				}
				return nil
			},
		}
		child.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
		command.AddCommand(child)
	}
	return command
}

func runWindowsManagedHooksTeardown(
	action string,
) (windowsManagedHooksTeardownReport, error) {
	report := windowsManagedHooksTeardownReport{
		SchemaVersion: windowsManagedHooksTeardownSchema,
		Action:        action,
		Results:       []windowsManagedHooksTeardownResult{},
	}
	fail := func(err error) (windowsManagedHooksTeardownReport, error) {
		report.OK = false
		report.Error = err.Error()
		report.SucceededCount = 0
		report.VerifiedCleanCount = 0
		report.VerifiedInstalledCount = 0
		report.FailedCount = report.TargetCount
		for index := range report.Results {
			report.Results[index].OK = false
			report.Results[index].Error = err.Error()
		}
		return report, err
	}
	if action != "prepare" && action != "verify" && action != "rollback" {
		return fail(fmt.Errorf("unsupported managed-hook teardown action %q", action))
	}
	// Authorization intentionally precedes protected layout discovery.
	if err := enterpriseHooksNativePlatformPreflight(); err != nil {
		return fail(err)
	}
	opts, err := resolveWindowsCodexRequirementsLayout("remove")
	if err != nil {
		return fail(err)
	}
	ownershipPath := opts.OwnershipPath
	installDir := filepath.Dir(ownershipPath)
	stateRoot := filepath.Dir(installDir)
	if ownershipPath == "" || !filepath.IsAbs(ownershipPath) ||
		strings.TrimSpace(ownershipPath) != ownershipPath ||
		filepath.Clean(ownershipPath) != ownershipPath ||
		!strings.EqualFold(filepath.Base(ownershipPath), "codex-requirements-ownership.json") ||
		!strings.EqualFold(filepath.Base(installDir), "install") ||
		stateRoot == installDir || stateRoot == filepath.Dir(stateRoot) {
		return fail(errors.New("managed-hook teardown received a noncanonical protected ownership path"))
	}
	runtimeDir, err := exactWindowsCodexLayoutEnv("DEFENSECLAW_HOME")
	if err != nil {
		return fail(err)
	}
	expectedStateRoot := filepath.Dir(runtimeDir)
	if !strings.EqualFold(filepath.Base(runtimeDir), "runtime") ||
		!sameWindowsEnterprisePathCLI(stateRoot, expectedStateRoot) {
		return fail(errors.New("managed-hook teardown ownership path does not match the protected state root"))
	}
	if err := managed.ValidateTrustedRuntimeDir(
		stateRoot,
		"Windows enterprise managed-hook teardown state root",
	); err != nil {
		return fail(err)
	}
	report.ManifestPath = filepath.Join(stateRoot, "hook-guardian", "targets.yaml")
	report.JournalPath = filepath.Join(
		stateRoot,
		"install",
		windowsManagedHooksTeardownJournalFile,
	)
	if !sameWindowsEnterprisePathCLI(
		report.JournalPath,
		filepath.Join(installDir, windowsManagedHooksTeardownJournalFile),
	) {
		return fail(errors.New("managed-hook teardown derived a noncanonical protected layout"))
	}
	if err := managed.ValidateTrustedFilePath(
		report.ManifestPath,
		"Windows enterprise hook target manifest",
	); err != nil {
		return fail(err)
	}
	manifest, err := enterprisehooks.LoadManifest(report.ManifestPath)
	if err != nil {
		return fail(err)
	}
	targets, claudeTargets, codexTargets, err := windowsManagedHooksTeardownTargets(manifest)
	if err != nil {
		return fail(err)
	}
	report.TargetCount = len(targets)
	report.Results = make([]windowsManagedHooksTeardownResult, 0, len(targets))
	for _, target := range targets {
		report.Results = append(report.Results, windowsManagedHooksTeardownResult{
			Connector: target.Connector,
			SID:       target.SID,
		})
	}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(targets)
	if err != nil {
		return fail(err)
	}
	identity := windowsManagedHooksTeardownJournal{
		SchemaVersion:       windowsManagedHooksTeardownSchema,
		ManifestPath:        report.ManifestPath,
		ManifestFingerprint: fingerprint,
		HookBinary:          opts.HookBinary,
		GatewayAddr:         opts.GatewayAddr,
		GatewayServiceName:  opts.GatewayServiceName,
		Targets:             targets,
	}
	claudeOpts := enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions{
		HookExecutable:     opts.HookBinary,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		TargetSIDs:         claudeTargets,
	}

	switch action {
	case "prepare":
		err = prepareWindowsManagedHooksTeardown(
			opts,
			claudeOpts,
			codexTargets,
			identity,
			report.JournalPath,
		)
		if err == nil {
			report.RollbackReady = true
			report.SafeToRemoveBinary = true
			report.VerifiedCleanCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	case "verify":
		var journal windowsManagedHooksTeardownJournal
		journal, err = readWindowsManagedHooksTeardownJournal(report.JournalPath)
		if err == nil {
			err = validateWindowsManagedHooksTeardownJournal(journal, identity)
		}
		if err == nil && journal.Phase != "prepared" {
			err = fmt.Errorf(
				"managed-hook teardown journal phase is %q, expected prepared",
				journal.Phase,
			)
		}
		if err == nil {
			_, err = verifyWindowsManagedHooksTeardownClean(opts)
		}
		if err == nil {
			report.RollbackReady = true
			report.SafeToRemoveBinary = true
			report.VerifiedCleanCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	case "rollback":
		var journal windowsManagedHooksTeardownJournal
		journal, err = readWindowsManagedHooksTeardownJournal(report.JournalPath)
		if err == nil {
			err = validateWindowsManagedHooksTeardownJournal(journal, identity)
		}
		if err == nil && journal.Phase != "captured" &&
			journal.Phase != "prepared" && journal.Phase != "rolled_back" {
			err = fmt.Errorf(
				"managed-hook teardown journal phase %q cannot be rolled back",
				journal.Phase,
			)
		}
		if err == nil {
			err = rollbackWindowsManagedHooksTeardown(
				opts,
				claudeOpts,
				codexTargets,
				journal,
				report.JournalPath,
			)
		}
		if err == nil {
			report.RollbackCompleted = true
			report.VerifiedInstalledCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	}
	if err != nil {
		return fail(err)
	}
	for index := range report.Results {
		report.Results[index].OK = true
	}
	report.FailedCount = 0
	report.SurvivingOwnedPathReferences = 0
	report.OK = true
	return report, nil
}

func prepareWindowsManagedHooksTeardown(
	opts connector.WindowsCodexMachineRequirementsOptions,
	claudeOpts enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions,
	codexTargets []connector.WindowsCodexManagedRuntimeTarget,
	identity windowsManagedHooksTeardownJournal,
	journalPath string,
) error {
	if existing, err := readWindowsManagedHooksTeardownJournal(journalPath); err == nil {
		if validateErr := validateWindowsManagedHooksTeardownJournal(existing, identity); validateErr != nil {
			return validateErr
		}
		switch existing.Phase {
		case "prepared":
			if _, verifyErr := verifyWindowsManagedHooksTeardownClean(opts); verifyErr == nil {
				return nil
			}
			// A committed uninstall can crash after transaction completion but
			// before PowerShell retires this protected journal. If a later
			// reinstall has restored the exact manifest enrollment, treat the
			// old prepared record as stale and capture a fresh preimage below.
			// Partial or mismatched enrollment still fails the installed-state
			// verification before any mutation.
		case "captured":
			return errors.New(
				"managed-hook teardown has an incomplete captured transaction; rollback is required",
			)
		case "rolled_back":
			// A subsequent lifecycle attempt may safely replace a completed
			// journal after the active set is verified below.
		default:
			return fmt.Errorf("unsupported managed-hook teardown journal phase %q", existing.Phase)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := verifyWindowsManagedHooksTeardownInstalled(
		opts,
		claudeOpts.TargetSIDs,
		codexTargets,
	); err != nil {
		return err
	}

	var captured enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot
	persisted := false
	var err error
	captured, err = enterprisehooks.PrepareWindowsClaudeManagedPolicyTeardown(
		claudeOpts,
		func(snapshot enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot) error {
			journal := identity
			journal.Phase = "captured"
			journal.Claude = snapshot
			if err := writeWindowsManagedHooksTeardownJournal(journalPath, journal); err != nil {
				return err
			}
			persisted = true
			return nil
		},
	)
	if err != nil {
		return err
	}
	if !persisted {
		return errors.New("managed-hook teardown did not durably publish its rollback journal")
	}
	restoreOnFailure := func(cause error) error {
		var failures []string
		if restoreErr := enterprisehooks.RestoreWindowsClaudeManagedPolicyTeardown(
			claudeOpts,
			captured,
		); restoreErr != nil {
			failures = append(failures, restoreErr.Error())
		}
		if len(codexTargets) != 0 {
			if restoreErr := restoreWindowsCodexManagedHooks(opts, codexTargets); restoreErr != nil {
				failures = append(failures, restoreErr.Error())
			}
		}
		if len(failures) != 0 {
			return fmt.Errorf(
				"%v (managed-hook teardown rollback failed: %s)",
				cause,
				strings.Join(failures, "; "),
			)
		}
		return cause
	}

	removeReport, err := connector.RemoveWindowsCodexMachineRequirements(opts)
	if err != nil {
		return restoreOnFailure(err)
	}
	if !removeReport.OK || !removeReport.SafeToRemoveBinary ||
		removeReport.SurvivingOwnedPathReferences != 0 {
		return restoreOnFailure(
			errors.New("Codex managed-hook removal was not reference-clean"),
		)
	}
	if _, err := verifyWindowsManagedHooksTeardownClean(opts); err != nil {
		return restoreOnFailure(err)
	}
	journal := identity
	journal.Phase = "prepared"
	journal.Claude = captured
	if err := writeWindowsManagedHooksTeardownJournal(journalPath, journal); err != nil {
		return restoreOnFailure(err)
	}
	return nil
}

func rollbackWindowsManagedHooksTeardown(
	opts connector.WindowsCodexMachineRequirementsOptions,
	claudeOpts enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions,
	codexTargets []connector.WindowsCodexManagedRuntimeTarget,
	journal windowsManagedHooksTeardownJournal,
	journalPath string,
) error {
	if err := enterprisehooks.RestoreWindowsClaudeManagedPolicyTeardown(
		claudeOpts,
		journal.Claude,
	); err != nil {
		return err
	}
	if len(codexTargets) != 0 {
		if err := restoreWindowsCodexManagedHooks(opts, codexTargets); err != nil {
			return err
		}
	} else {
		disabled := opts
		disabled.CodexTargetEnabled = false
		codexReport, codexErr := connector.VerifyWindowsCodexMachineRequirements(disabled)
		if codexErr != nil || !codexReport.OK ||
			!codexReport.SafeToRemoveBinary ||
			codexReport.SurvivingOwnedPathReferences != 0 {
			if codexErr != nil {
				return codexErr
			}
			return errors.New("Codex machine policy is not clean after teardown rollback")
		}
	}
	if err := verifyWindowsManagedHooksTeardownInstalled(
		opts,
		claudeOpts.TargetSIDs,
		codexTargets,
	); err != nil {
		return err
	}
	journal.Phase = "rolled_back"
	return writeWindowsManagedHooksTeardownJournal(journalPath, journal)
}

func restoreWindowsCodexManagedHooks(
	opts connector.WindowsCodexMachineRequirementsOptions,
	targets []connector.WindowsCodexManagedRuntimeTarget,
) error {
	opts.CodexTargetEnabled = true
	report, err := connector.ReconcileWindowsCodexMachineRequirements(opts)
	if err != nil {
		return err
	}
	if !report.OK {
		return errors.New("Codex requirements rollback reconcile did not complete")
	}
	if err := connector.PublishWindowsCodexManagedRuntimeTargets(opts, targets); err != nil {
		return err
	}
	report, err = connector.VerifyWindowsCodexMachineRequirements(opts)
	if err != nil {
		return err
	}
	if !report.OK {
		return errors.New("Codex requirements rollback verification did not complete")
	}
	return nil
}

func verifyWindowsManagedHooksTeardownClean(
	opts connector.WindowsCodexMachineRequirementsOptions,
) (int, error) {
	if err := enterprisehooks.VerifyWindowsClaudeManagedPolicyTeardown(); err != nil {
		return 0, err
	}
	disabled := opts
	disabled.CodexTargetEnabled = false
	report, err := connector.VerifyWindowsCodexMachineRequirements(disabled)
	if err != nil {
		return report.SurvivingOwnedPathReferences, err
	}
	if !report.OK || !report.SafeToRemoveBinary ||
		report.SurvivingOwnedPathReferences != 0 {
		return report.SurvivingOwnedPathReferences, errors.New(
			"Codex machine requirements are not clean after managed-hook teardown",
		)
	}
	return 0, nil
}

func verifyWindowsManagedHooksTeardownInstalled(
	opts connector.WindowsCodexMachineRequirementsOptions,
	claudeTargets []string,
	codexTargets []connector.WindowsCodexManagedRuntimeTarget,
) error {
	currentClaude, claudeActive, err := enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
	if err != nil {
		return err
	}
	if claudeActive != (len(claudeTargets) != 0) ||
		!equalWindowsEnterpriseStringSet(currentClaude, claudeTargets) {
		return errors.New("Claude machine enrollment does not match the teardown manifest")
	}
	registry, err := connector.ResolveWindowsCodexManagedRuntimeRegistry(opts.HookBinary)
	if err != nil {
		return err
	}
	if registry.Active != (len(codexTargets) != 0) ||
		len(registry.Targets) != len(codexTargets) {
		return errors.New("Codex machine enrollment does not match the teardown manifest")
	}
	current := append([]connector.WindowsCodexManagedRuntimeTarget(nil), registry.Targets...)
	sort.Slice(current, func(i, j int) bool { return current[i].SID < current[j].SID })
	for index := range codexTargets {
		if current[index].SID != codexTargets[index].SID ||
			!sameWindowsEnterprisePathCLI(current[index].DataDir, codexTargets[index].DataDir) {
			return errors.New("Codex machine enrollment does not match the teardown manifest")
		}
	}
	return nil
}

func windowsManagedHooksTeardownTargets(
	manifest enterprisehooks.Manifest,
) (
	[]windowsManagedHooksTeardownTarget,
	[]string,
	[]connector.WindowsCodexManagedRuntimeTarget,
	error,
) {
	targets := make([]windowsManagedHooksTeardownTarget, 0, len(manifest.Targets))
	claude := make([]string, 0, len(manifest.Targets))
	codex := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		sid, err := windows.StringToSid(strings.TrimSpace(target.SID))
		if err != nil || sid == nil {
			return nil, nil, nil, fmt.Errorf("invalid managed-hook teardown SID %q", target.SID)
		}
		connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
		if connectorName != "claudecode" && connectorName != "codex" {
			return nil, nil, nil, fmt.Errorf(
				"managed-hook teardown does not support connector %q",
				target.Connector,
			)
		}
		dataDir := filepath.Join(filepath.Clean(target.UserHome), ".defenseclaw")
		if configured := strings.TrimSpace(target.DataDir); configured != "" {
			configured, err = filepath.Abs(configured)
			if err != nil {
				return nil, nil, nil, err
			}
			configured = filepath.Clean(configured)
			if !sameWindowsEnterprisePathCLI(configured, dataDir) {
				return nil, nil, nil, fmt.Errorf(
					"managed-hook teardown target %s data_dir does not equal canonical %s",
					sid,
					dataDir,
				)
			}
		}
		row := windowsManagedHooksTeardownTarget{
			Connector:    connectorName,
			SID:          sid.String(),
			DataDir:      dataDir,
			AgentVersion: strings.TrimSpace(target.AgentVersion),
		}
		targets = append(targets, row)
		switch connectorName {
		case "claudecode":
			claude = append(claude, row.SID)
		case "codex":
			codex = append(codex, connector.WindowsCodexManagedRuntimeTarget{
				SID:     row.SID,
				DataDir: row.DataDir,
			})
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Connector == targets[j].Connector {
			return targets[i].SID < targets[j].SID
		}
		return targets[i].Connector < targets[j].Connector
	})
	sort.Strings(claude)
	sort.Slice(codex, func(i, j int) bool { return codex[i].SID < codex[j].SID })
	return targets, claude, codex, nil
}

func windowsManagedHooksTeardownFingerprint(
	targets []windowsManagedHooksTeardownTarget,
) (string, error) {
	body, err := json.Marshal(targets)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateWindowsManagedHooksTeardownJournal(
	journal, identity windowsManagedHooksTeardownJournal,
) error {
	if journal.SchemaVersion != windowsManagedHooksTeardownSchema ||
		journal.ManifestPath != identity.ManifestPath ||
		journal.ManifestFingerprint != identity.ManifestFingerprint ||
		journal.HookBinary != identity.HookBinary ||
		journal.GatewayAddr != identity.GatewayAddr ||
		journal.GatewayServiceName != identity.GatewayServiceName ||
		len(journal.Targets) != len(identity.Targets) {
		return errors.New("managed-hook teardown journal does not match the protected deployment")
	}
	for index := range identity.Targets {
		if journal.Targets[index] != identity.Targets[index] {
			return errors.New("managed-hook teardown journal target set changed")
		}
	}
	if journal.Claude.PolicyExisted != journal.Claude.StateExisted ||
		len(journal.Claude.Policy) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Claude.State) > windowsManagedHooksTeardownJournalMax {
		return errors.New("managed-hook teardown journal contains an invalid Claude snapshot")
	}
	return nil
}

func readWindowsManagedHooksTeardownJournal(
	path string,
) (windowsManagedHooksTeardownJournal, error) {
	var journal windowsManagedHooksTeardownJournal
	info, err := os.Lstat(path)
	if err != nil {
		return journal, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() > windowsManagedHooksTeardownJournalMax {
		return journal, errors.New(
			"managed-hook teardown journal is not a bounded regular non-link file",
		)
	}
	if err := managed.ValidateTrustedFilePath(path, "managed-hook teardown journal"); err != nil {
		return journal, err
	}
	file, err := os.Open(path)
	if err != nil {
		return journal, err
	}
	decoder := json.NewDecoder(io.LimitReader(
		file,
		windowsManagedHooksTeardownJournalMax+1,
	))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		_ = file.Close()
		return journal, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		_ = file.Close()
		if err == nil {
			return journal, errors.New("managed-hook teardown journal contains trailing JSON")
		}
		return journal, err
	}
	if err := file.Close(); err != nil {
		return journal, err
	}
	return journal, nil
}

func writeWindowsManagedHooksTeardownJournal(
	path string,
	journal windowsManagedHooksTeardownJournal,
) error {
	body, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > windowsManagedHooksTeardownJournalMax {
		return fmt.Errorf(
			"managed-hook teardown journal exceeds %d-byte limit",
			windowsManagedHooksTeardownJournalMax,
		)
	}
	parent := filepath.Dir(path)
	if err := managed.ValidateTrustedRuntimeDir(
		parent,
		"managed-hook teardown journal parent",
	); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("managed-hook teardown journal is not a regular non-link file")
		}
		if err := managed.ValidateTrustedFilePath(path, "managed-hook teardown journal"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".managed-hooks-teardown-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	if err := setEnterpriseWindowsManagedProtection(
		tmpPath,
		administrators,
		nil,
		0,
		false,
	); err != nil {
		return err
	}
	if err := safefile.ReplaceFile(tmpPath, path); err != nil {
		return err
	}
	if err := setEnterpriseWindowsManagedProtection(
		path,
		administrators,
		nil,
		0,
		false,
	); err != nil {
		return err
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(persisted, body) {
		return errors.New("managed-hook teardown journal changed during publication")
	}
	return managed.ValidateTrustedFilePath(path, "managed-hook teardown journal")
}
