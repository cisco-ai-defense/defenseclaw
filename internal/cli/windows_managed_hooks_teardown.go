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
	windowsManagedHooksTeardownSchema      = 4
	windowsManagedHooksTeardownJournalMax  = 32 << 20
	windowsManagedHooksTeardownJournalFile = "managed-hooks-teardown-journal.json"
)

type windowsManagedHooksTeardownTarget struct {
	Connector    string `json:"connector"`
	SID          string `json:"sid"`
	DataDir      string `json:"data_dir"`
	AgentVersion string `json:"agent_version"`
}

type windowsManagedHooksTeardownJournal struct {
	SchemaVersion       int                                                           `json:"schema_version"`
	Phase               string                                                        `json:"phase"`
	ManifestPath        string                                                        `json:"manifest_path"`
	ManifestFingerprint string                                                        `json:"manifest_fingerprint"`
	HookBinary          string                                                        `json:"hook_binary"`
	GatewayAddr         string                                                        `json:"gateway_addr"`
	GatewayServiceName  string                                                        `json:"gateway_service_name"`
	Targets             []windowsManagedHooksTeardownTarget                           `json:"targets"`
	ClaudeTargetSIDs    []string                                                      `json:"claude_target_sids"`
	Claude              enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot    `json:"claude"`
	CursorTargets       []enterprisehooks.WindowsCursorManagedRuntimeTarget           `json:"cursor_targets"`
	Cursor              enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot    `json:"cursor"`
	SelectorTargets     []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot `json:"selector_targets"`
}

type windowsManagedHooksTeardownMachineCapture struct {
	claudeOpts     enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions
	claudeSnapshot enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot
	cursorOpts     enterprisehooks.WindowsCursorManagedPolicyTeardownOptions
	cursorSnapshot enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot
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
	EnrollmentTargetCount        int                                 `json:"enrollment_target_count"`
	SucceededCount               int                                 `json:"succeeded_count"`
	VerifiedCleanCount           int                                 `json:"verified_clean_count"`
	VerifiedInstalledCount       int                                 `json:"verified_installed_count"`
	FailedCount                  int                                 `json:"failed_count"`
	SurvivingOwnedPathReferences int                                 `json:"surviving_owned_path_references"`
	RollbackReady                bool                                `json:"rollback_ready"`
	SafeToRemoveBinary           bool                                `json:"safe_to_remove_binary"`
	RollbackCompleted            bool                                `json:"rollback_completed"`
	FinalizationCompleted        bool                                `json:"finalization_completed"`
	CollectedGenerationCount     int                                 `json:"collected_generation_count"`
	Results                      []windowsManagedHooksTeardownResult `json:"results"`
	Error                        string                              `json:"error,omitempty"`
}

func newWindowsManagedHooksTeardownCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "teardown-managed-hooks",
		Short:  "Transactionally revoke managed hook machine wiring",
		Hidden: true,
	}
	for _, action := range []string{"prepare", "verify", "rollback", "finalize"} {
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
		if !report.RollbackCompleted {
			report.VerifiedInstalledCount = 0
		}
		report.FailedCount = report.TargetCount
		for index := range report.Results {
			report.Results[index].OK = false
			report.Results[index].Error = err.Error()
		}
		return report, err
	}
	if action != "prepare" && action != "verify" && action != "rollback" &&
		action != "finalize" {
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
	targets, claudeTargets, codexTargets, cursorTargets, err := windowsManagedHooksTeardownTargets(manifest)
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
	switch action {
	case "prepare":
		currentClaude, claudeActive, readErr :=
			enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
		if readErr != nil {
			err = readErr
			break
		}
		currentClaude, err = windowsManagedHooksPartialClaudeTargets(
			claudeTargets,
			currentClaude,
			claudeActive,
		)
		if err != nil {
			break
		}
		identity.ClaudeTargetSIDs = currentClaude
		currentCursor, cursorActive, readCursorErr :=
			enterprisehooks.ReadWindowsCursorManagedPolicyTargets()
		if readCursorErr != nil {
			err = readCursorErr
			break
		}
		currentCursor, err = windowsManagedHooksPartialCursorTargets(
			cursorTargets,
			currentCursor,
			cursorActive,
		)
		if err != nil {
			break
		}
		identity.CursorTargets = currentCursor
		report.EnrollmentTargetCount = len(currentClaude) + len(codexTargets) + len(currentCursor)
		var rollbackCompleted bool
		var surviving int
		rollbackCompleted, surviving, err = prepareWindowsManagedHooksTeardown(
			opts,
			windowsManagedHooksClaudeOptions(opts, currentClaude),
			windowsManagedHooksCursorOptions(opts, currentCursor),
			codexTargets,
			identity,
			report.JournalPath,
		)
		report.SurvivingOwnedPathReferences = surviving
		if rollbackCompleted {
			report.RollbackCompleted = true
			report.VerifiedInstalledCount = report.EnrollmentTargetCount
		}
		if err == nil {
			report.RollbackReady = true
			report.SafeToRemoveBinary = false
			report.VerifiedCleanCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	case "verify":
		var journal windowsManagedHooksTeardownJournal
		journal, err = readWindowsManagedHooksTeardownJournal(report.JournalPath)
		if err == nil {
			err = validateWindowsManagedHooksTeardownJournal(journal, identity)
		}
		if err == nil {
			report.EnrollmentTargetCount =
				len(journal.ClaudeTargetSIDs) + len(codexTargets) + len(journal.CursorTargets)
		}
		if err == nil && journal.Phase != "prepared" {
			err = fmt.Errorf(
				"managed-hook teardown journal phase is %q, expected prepared",
				journal.Phase,
			)
		}
		if err == nil {
			var surviving int
			surviving, err = verifyWindowsManagedHooksTeardownClean(opts, journal.Targets)
			report.SurvivingOwnedPathReferences = surviving
		}
		if err == nil {
			report.RollbackReady = true
			report.SafeToRemoveBinary = false
			report.VerifiedCleanCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	case "rollback":
		var journal windowsManagedHooksTeardownJournal
		journal, err = readWindowsManagedHooksTeardownJournal(report.JournalPath)
		if err == nil {
			err = validateWindowsManagedHooksTeardownJournal(journal, identity)
		}
		if err == nil {
			report.EnrollmentTargetCount =
				len(journal.ClaudeTargetSIDs) + len(codexTargets) + len(journal.CursorTargets)
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
				windowsManagedHooksClaudeOptions(opts, journal.ClaudeTargetSIDs),
				windowsManagedHooksCursorOptions(opts, journal.CursorTargets),
				codexTargets,
				journal,
				report.JournalPath,
			)
		}
		if err == nil {
			report.RollbackCompleted = true
			report.VerifiedInstalledCount = report.EnrollmentTargetCount
			report.SucceededCount = report.TargetCount
		}
	case "finalize":
		var journal windowsManagedHooksTeardownJournal
		journal, err = readWindowsManagedHooksTeardownJournal(report.JournalPath)
		if err == nil {
			err = validateWindowsManagedHooksTeardownJournal(journal, identity)
		}
		if err == nil && journal.Phase != "prepared" && journal.Phase != "finalized" {
			err = fmt.Errorf(
				"managed-hook teardown journal phase %q cannot be finalized",
				journal.Phase,
			)
		}
		if err == nil {
			var surviving int
			surviving, err = verifyWindowsManagedHooksTeardownClean(opts, journal.Targets)
			report.SurvivingOwnedPathReferences = surviving
		}
		if err == nil {
			report.CollectedGenerationCount, err = finalizeWindowsManagedHooksTeardown(
				journal,
				report.JournalPath,
			)
		}
		if err == nil {
			report.FinalizationCompleted = true
			report.SafeToRemoveBinary = true
			report.VerifiedCleanCount = report.TargetCount
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
	cursorOpts enterprisehooks.WindowsCursorManagedPolicyTeardownOptions,
	codexTargets []connector.WindowsCodexManagedRuntimeTarget,
	identity windowsManagedHooksTeardownJournal,
	journalPath string,
) (bool, int, error) {
	if existing, err := readWindowsManagedHooksTeardownJournal(journalPath); err == nil {
		if validateErr := validateWindowsManagedHooksTeardownJournal(existing, identity); validateErr != nil {
			return false, 0, validateErr
		}
		switch existing.Phase {
		case "prepared":
			surviving, verifyErr := verifyWindowsManagedHooksTeardownClean(
				opts,
				existing.Targets,
			)
			if verifyErr == nil {
				return false, surviving, nil
			}
			// A committed uninstall can crash after transaction completion but
			// before PowerShell retires this protected journal. If a later
			// reinstall has restored the exact manifest enrollment, treat the
			// old prepared record as stale and capture a fresh preimage below.
			// Partial or mismatched enrollment still fails the installed-state
			// verification before any mutation.
		case "captured":
			return false, 0, errors.New(
				"managed-hook teardown has an incomplete captured transaction; rollback is required",
			)
		case "rolled_back", "finalized":
			// A subsequent lifecycle attempt may safely replace a completed
			// journal after the active set is verified below.
		default:
			return false, 0, fmt.Errorf("unsupported managed-hook teardown journal phase %q", existing.Phase)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, 0, err
	}
	if err := verifyWindowsManagedHooksTeardownInstalled(
		opts,
		identity.Targets,
		claudeOpts.TargetSIDs,
		codexTargets,
		cursorOpts.Targets,
		nil,
	); err != nil {
		return false, 0, err
	}
	selectorTargets, err := captureWindowsManagedHooksRuntimeSelectors(
		identity.Targets,
		identity.HookBinary,
	)
	if err != nil {
		return false, 0, err
	}
	identity.SelectorTargets = selectorTargets
	if err := verifyWindowsManagedHooksTeardownInstalled(
		opts,
		identity.Targets,
		claudeOpts.TargetSIDs,
		codexTargets,
		cursorOpts.Targets,
		identity.SelectorTargets,
	); err != nil {
		return false, 0, err
	}

	var captured enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot
	var capturedCursor enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot
	persisted := false
	captured, err = enterprisehooks.PrepareWindowsClaudeManagedPolicyTeardown(
		claudeOpts,
		func(snapshot enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot) error {
			var cursorErr error
			capturedCursor, cursorErr = enterprisehooks.PrepareWindowsCursorManagedPolicyTeardown(
				cursorOpts,
				func(cursorSnapshot enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot) error {
					journal := identity
					journal.Phase = "captured"
					journal.Claude = snapshot
					journal.Cursor = cursorSnapshot
					if err := writeWindowsManagedHooksTeardownJournal(journalPath, journal); err != nil {
						return err
					}
					persisted = true
					return nil
				},
			)
			return cursorErr
		},
	)
	restoreOnFailure := func(cause error, surviving int) (bool, int, error) {
		journal := identity
		journal.Phase = "captured"
		journal.Claude = captured
		journal.Cursor = capturedCursor
		if rollbackErr := rollbackWindowsManagedHooksTeardown(
			opts,
			claudeOpts,
			cursorOpts,
			codexTargets,
			journal,
			journalPath,
		); rollbackErr != nil {
			return false, surviving, fmt.Errorf(
				"%v (managed-hook teardown rollback failed: %v)",
				cause,
				rollbackErr,
			)
		}
		return true, surviving, cause
	}
	if err != nil {
		if persisted {
			return restoreOnFailure(err, 0)
		}
		return false, 0, err
	}
	if !persisted {
		return false, 0, errors.New("managed-hook teardown did not durably publish its rollback journal")
	}

	removeReport, err := connector.RemoveWindowsCodexMachineRequirements(opts)
	if err != nil {
		return restoreOnFailure(err, removeReport.SurvivingOwnedPathReferences)
	}
	if !removeReport.OK || !removeReport.SafeToRemoveBinary ||
		removeReport.SurvivingOwnedPathReferences != 0 {
		return restoreOnFailure(
			errors.New("Codex managed-hook removal was not reference-clean"),
			removeReport.SurvivingOwnedPathReferences,
		)
	}
	if err := removeWindowsManagedHooksRuntimeSelectors(
		identity.Targets,
		identity.HookBinary,
	); err != nil {
		return restoreOnFailure(err, 0)
	}
	surviving, err := verifyWindowsManagedHooksTeardownClean(opts, identity.Targets)
	if err != nil {
		return restoreOnFailure(err, surviving)
	}
	journal := identity
	journal.Phase = "prepared"
	journal.Claude = captured
	journal.Cursor = capturedCursor
	if err := writeWindowsManagedHooksTeardownJournal(journalPath, journal); err != nil {
		return restoreOnFailure(err, surviving)
	}
	return false, surviving, nil
}

func completeWindowsManagedHooksTeardownRollback(
	journal windowsManagedHooksTeardownJournal,
	restore func() error,
	verify func() error,
	persist func(windowsManagedHooksTeardownJournal) error,
) error {
	switch journal.Phase {
	case "captured", "prepared", "rolled_back":
	default:
		return fmt.Errorf(
			"managed-hook teardown journal phase %q cannot be rolled back",
			journal.Phase,
		)
	}
	verificationErr := verify()
	if verificationErr != nil {
		if journal.Phase == "rolled_back" {
			return verificationErr
		}
		if err := restore(); err != nil {
			return err
		}
		if err := verify(); err != nil {
			return err
		}
	}
	if journal.Phase == "rolled_back" {
		// A failed prepare may already have restored and authenticated every
		// target. Revalidate that state without repeating file replacement.
		return nil
	}
	journal.Phase = "rolled_back"
	return persist(journal)
}

func rollbackWindowsManagedHooksTeardown(
	opts connector.WindowsCodexMachineRequirementsOptions,
	claudeOpts enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions,
	cursorOpts enterprisehooks.WindowsCursorManagedPolicyTeardownOptions,
	codexTargets []connector.WindowsCodexManagedRuntimeTarget,
	journal windowsManagedHooksTeardownJournal,
	journalPath string,
) error {
	return completeWindowsManagedHooksTeardownRollback(
		journal,
		func() error {
			if err := restoreWindowsManagedHooksRuntimeSelectors(
				journal.Targets,
				journal.HookBinary,
				journal.SelectorTargets,
			); err != nil {
				return err
			}
			current, err := captureWindowsManagedHooksTeardownMachineState(
				claudeOpts,
				cursorOpts,
				journal,
			)
			if err != nil {
				return err
			}
			return restoreWindowsManagedHooksTeardownComposite(
				func() error {
					return enterprisehooks.RestoreWindowsClaudeManagedPolicyTeardown(
						claudeOpts,
						journal.Claude,
					)
				},
				func() error {
					if current.cursorSnapshot.PolicyActive {
						return enterprisehooks.RestoreWindowsCursorManagedPolicySnapshot(
							cursorOpts,
							current.cursorOpts,
							journal.Cursor,
						)
					}
					return enterprisehooks.RestoreWindowsCursorManagedPolicyTeardown(
						cursorOpts,
						journal.Cursor,
					)
				},
				func() error {
					if len(codexTargets) != 0 {
						return restoreWindowsCodexManagedHooks(opts, codexTargets)
					}
					disabled := opts
					disabled.CodexTargetEnabled = false
					codexReport, codexErr := connector.VerifyWindowsCodexMachineRequirements(disabled)
					if codexErr != nil {
						return codexErr
					}
					if !codexReport.OK || !codexReport.SafeToRemoveBinary ||
						codexReport.SurvivingOwnedPathReferences != 0 {
						return errors.New("Codex machine policy is not clean after teardown rollback")
					}
					return nil
				},
				func() error {
					return enterprisehooks.RestoreWindowsClaudeManagedPolicySnapshot(
						current.claudeOpts,
						claudeOpts,
						current.claudeSnapshot,
					)
				},
				func() error {
					return enterprisehooks.RestoreWindowsCursorManagedPolicySnapshot(
						current.cursorOpts,
						cursorOpts,
						current.cursorSnapshot,
					)
				},
			)
		},
		func() error {
			return verifyWindowsManagedHooksTeardownInstalled(
				opts,
				journal.Targets,
				claudeOpts.TargetSIDs,
				codexTargets,
				cursorOpts.Targets,
				journal.SelectorTargets,
			)
		},
		func(updated windowsManagedHooksTeardownJournal) error {
			return writeWindowsManagedHooksTeardownJournal(journalPath, updated)
		},
	)
}

func captureWindowsManagedHooksTeardownMachineState(
	claudeOpts enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions,
	cursorOpts enterprisehooks.WindowsCursorManagedPolicyTeardownOptions,
	journal windowsManagedHooksTeardownJournal,
) (windowsManagedHooksTeardownMachineCapture, error) {
	var result windowsManagedHooksTeardownMachineCapture
	currentClaude, claudeActive, err := enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
	if err != nil {
		return result, fmt.Errorf("capture current Claude teardown enrollment: %w", err)
	}
	currentClaude, err = windowsManagedHooksPartialClaudeTargets(
		claudeOpts.TargetSIDs,
		currentClaude,
		claudeActive,
	)
	if err != nil {
		return result, err
	}
	result.claudeOpts = claudeOpts
	result.claudeOpts.TargetSIDs = append([]string(nil), currentClaude...)
	result.claudeSnapshot, err = enterprisehooks.CaptureWindowsClaudeManagedPolicySnapshot(
		result.claudeOpts,
	)
	if err != nil {
		return result, fmt.Errorf("capture current Claude teardown policy: %w", err)
	}

	captureCursor := func() error {
		currentCursor, cursorActive, cursorErr := enterprisehooks.ReadWindowsCursorManagedPolicyTargets()
		if cursorErr != nil {
			return fmt.Errorf("capture current Cursor teardown enrollment: %w", cursorErr)
		}
		currentCursor, cursorErr = windowsManagedHooksPartialCursorTargets(
			cursorOpts.Targets,
			currentCursor,
			cursorActive,
		)
		if cursorErr != nil {
			return cursorErr
		}
		result.cursorOpts = cursorOpts
		result.cursorOpts.Targets = append(
			[]enterprisehooks.WindowsCursorManagedRuntimeTarget(nil),
			currentCursor...,
		)
		result.cursorSnapshot, cursorErr = enterprisehooks.CaptureWindowsCursorManagedPolicySnapshot(
			result.cursorOpts,
		)
		if cursorErr != nil {
			return fmt.Errorf("capture current Cursor teardown policy: %w", cursorErr)
		}
		return nil
	}
	initialCursorErr := captureCursor()
	// Cursor deactivation is journaled before Claude is removed. A process
	// crash can therefore leave Cursor at a recognized write prefix while
	// Claude is still the exact installed preimage. Only in that state may the
	// authenticated Cursor teardown restore normalize the partial transaction
	// before we recapture both sides for composite compensation.
	if err := recoverWindowsManagedHooksCursorTeardownCapture(
		initialCursorErr,
		journal.Cursor.PolicyActive &&
			windowsManagedHooksClaudeSnapshotsEqual(result.claudeSnapshot, journal.Claude),
		func() error {
			return enterprisehooks.RestoreWindowsCursorManagedPolicyTeardown(
				cursorOpts,
				journal.Cursor,
			)
		},
		captureCursor,
	); err != nil {
		return result, err
	}
	return result, nil
}

func recoverWindowsManagedHooksCursorTeardownCapture(
	initialCaptureErr error,
	allowJournalHeal bool,
	heal func() error,
	recapture func() error,
) error {
	if initialCaptureErr == nil {
		return nil
	}
	if !allowJournalHeal {
		return initialCaptureErr
	}
	if healErr := heal(); healErr != nil {
		return errors.Join(
			initialCaptureErr,
			fmt.Errorf("heal partial Cursor teardown before rollback: %w", healErr),
		)
	}
	if recaptureErr := recapture(); recaptureErr != nil {
		return errors.Join(
			initialCaptureErr,
			fmt.Errorf("recapture healed Cursor teardown policy: %w", recaptureErr),
		)
	}
	return nil
}

func windowsManagedHooksClaudeSnapshotsEqual(
	left, right enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot,
) bool {
	return left.PolicyExisted == right.PolicyExisted &&
		bytes.Equal(left.Policy, right.Policy) &&
		left.StateExisted == right.StateExisted &&
		bytes.Equal(left.State, right.State)
}

func restoreWindowsManagedHooksTeardownComposite(
	restoreClaude func() error,
	restoreCursor func() error,
	restoreCodex func() error,
	compensateClaude func() error,
	compensateCursor func() error,
) error {
	if err := restoreClaude(); err != nil {
		return err
	}
	if err := restoreCursor(); err != nil {
		if compensateErr := compensateClaude(); compensateErr != nil {
			return errors.Join(
				err,
				fmt.Errorf("restore pre-rollback Claude policy after Cursor failure: %w", compensateErr),
			)
		}
		return err
	}
	if err := restoreCodex(); err != nil {
		failures := []error{err}
		if compensateErr := compensateCursor(); compensateErr != nil {
			failures = append(failures, fmt.Errorf(
				"restore pre-rollback Cursor policy after Codex failure: %w",
				compensateErr,
			))
		}
		if compensateErr := compensateClaude(); compensateErr != nil {
			failures = append(failures, fmt.Errorf(
				"restore pre-rollback Claude policy after Codex failure: %w",
				compensateErr,
			))
		}
		return errors.Join(failures...)
	}
	return nil
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

func windowsManagedHooksRuntimeSelectorOptions(
	target windowsManagedHooksTeardownTarget,
	hookBinary string,
) enterprisehooks.WindowsManagedRuntimeSelectorSnapshotOptions {
	return enterprisehooks.WindowsManagedRuntimeSelectorSnapshotOptions{
		Connector:      target.Connector,
		TargetSID:      target.SID,
		DataDir:        target.DataDir,
		HookExecutable: hookBinary,
	}
}

func captureWindowsManagedHooksRuntimeSelectors(
	targets []windowsManagedHooksTeardownTarget,
	hookBinary string,
) ([]enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot, error) {
	snapshots := make(
		[]enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
		0,
		len(targets),
	)
	for _, target := range targets {
		snapshot, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
			windowsManagedHooksRuntimeSelectorOptions(target, hookBinary),
		)
		if err != nil {
			return nil, fmt.Errorf(
				"capture %s managed runtime selector target %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		if !snapshot.Existed || !snapshot.CAS.Exists {
			return nil, fmt.Errorf(
				"managed runtime selector is missing enrolled %s target %s",
				target.Connector,
				target.SID,
			)
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func removeWindowsManagedHooksRuntimeSelectors(
	targets []windowsManagedHooksTeardownTarget,
	hookBinary string,
) error {
	for _, target := range targets {
		_, err := enterprisehooks.RemoveWindowsManagedRuntimeGenerationEnrollment(
			enterprisehooks.WindowsManagedRuntimeGenerationRemovalOptions{
				Connector:                target.Connector,
				TargetSID:                target.SID,
				DataDir:                  target.DataDir,
				HookExecutable:           hookBinary,
				PrimaryEnrollmentRemoved: true,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"remove %s managed runtime selector target %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		current, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
			windowsManagedHooksRuntimeSelectorOptions(target, hookBinary),
		)
		if err != nil {
			return err
		}
		if current.Existed || current.CAS.Exists {
			return fmt.Errorf(
				"%s managed runtime selector target %s survived removal",
				target.Connector,
				target.SID,
			)
		}
	}
	return nil
}

func restoreWindowsManagedHooksRuntimeSelectors(
	targets []windowsManagedHooksTeardownTarget,
	hookBinary string,
	snapshots []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
) error {
	if len(snapshots) != len(targets) {
		return errors.New("managed runtime selector snapshot count does not match the teardown manifest")
	}
	for _, snapshot := range snapshots {
		target, ok := windowsManagedHooksTeardownTargetForSelector(snapshot, targets)
		if !ok {
			return errors.New("managed runtime selector snapshot does not match the teardown manifest")
		}
		current, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
			windowsManagedHooksRuntimeSelectorOptions(target, hookBinary),
		)
		if err != nil {
			return err
		}
		if current.CAS != snapshot.CAS && current.CAS.Exists {
			return enterprisehooks.ErrWindowsManagedRuntimeGenerationConflict
		}
		if err := enterprisehooks.RestoreWindowsManagedRuntimeSelectorTargetCAS(
			enterprisehooks.WindowsManagedRuntimeSelectorRestoreOptions{
				Snapshot:        snapshot,
				ExpectedCurrent: current.CAS,
			},
		); err != nil {
			return fmt.Errorf(
				"restore %s managed runtime selector target %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
	}
	return nil
}

func finalizeWindowsManagedHooksTeardown(
	journal windowsManagedHooksTeardownJournal,
	journalPath string,
) (int, error) {
	collected := 0
	for _, target := range journal.Targets {
		removed, err := enterprisehooks.GarbageCollectWindowsManagedRuntimeGenerations(
			enterprisehooks.WindowsManagedRuntimeGenerationGCOptions{
				Connector:      target.Connector,
				TargetSID:      target.SID,
				DataDir:        target.DataDir,
				HookExecutable: journal.HookBinary,
			},
		)
		if err != nil {
			return collected, fmt.Errorf(
				"finalize %s managed runtime generations for %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		collected += removed
	}
	journal.Phase = "finalized"
	if err := writeWindowsManagedHooksTeardownJournal(journalPath, journal); err != nil {
		return collected, err
	}
	return collected, nil
}

func windowsManagedHooksTeardownTargetForSelector(
	snapshot enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
	targets []windowsManagedHooksTeardownTarget,
) (windowsManagedHooksTeardownTarget, bool) {
	for _, target := range targets {
		if target.Connector == snapshot.Connector && target.SID == snapshot.TargetSID {
			return target, true
		}
	}
	return windowsManagedHooksTeardownTarget{}, false
}

func verifyWindowsManagedHooksTeardownClean(
	opts connector.WindowsCodexMachineRequirementsOptions,
	targets []windowsManagedHooksTeardownTarget,
) (int, error) {
	if err := enterprisehooks.VerifyWindowsClaudeManagedPolicyTeardown(); err != nil {
		return 0, err
	}
	if err := enterprisehooks.VerifyWindowsCursorManagedPolicyTeardown(); err != nil {
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
	for _, target := range targets {
		snapshot, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
			windowsManagedHooksRuntimeSelectorOptions(target, opts.HookBinary),
		)
		if err != nil {
			return 0, fmt.Errorf(
				"verify %s selector teardown for %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		if snapshot.Existed || snapshot.CAS.Exists {
			return 0, fmt.Errorf(
				"managed runtime selector still enrolls %s target %s",
				target.Connector,
				target.SID,
			)
		}
	}
	return 0, nil
}

func verifyWindowsManagedHooksTeardownInstalled(
	opts connector.WindowsCodexMachineRequirementsOptions,
	targets []windowsManagedHooksTeardownTarget,
	claudeTargets []string,
	codexTargets []connector.WindowsCodexManagedRuntimeTarget,
	cursorTargets []enterprisehooks.WindowsCursorManagedRuntimeTarget,
	selectorTargets []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
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
	currentCursor, cursorActive, err := enterprisehooks.ReadWindowsCursorManagedPolicyTargets()
	if err != nil {
		return err
	}
	if cursorActive != (len(cursorTargets) != 0) || len(currentCursor) != len(cursorTargets) {
		return errors.New("Cursor machine enrollment does not match the teardown manifest")
	}
	for index := range cursorTargets {
		if !strings.EqualFold(currentCursor[index].SID, cursorTargets[index].SID) ||
			!sameWindowsEnterprisePathCLI(currentCursor[index].DataDir, cursorTargets[index].DataDir) {
			return errors.New("Cursor machine enrollment does not match the teardown manifest")
		}
	}
	if selectorTargets != nil {
		if len(selectorTargets) != len(targets) {
			return errors.New("managed runtime selector snapshot count does not match the teardown manifest")
		}
		for _, expected := range selectorTargets {
			if !expected.Existed || !expected.CAS.Exists {
				return fmt.Errorf(
					"managed runtime selector did not enroll %s target %s before teardown",
					expected.Connector,
					expected.TargetSID,
				)
			}
			target, ok := windowsManagedHooksTeardownTargetForSelector(expected, targets)
			if !ok {
				return errors.New("managed runtime selector snapshot does not match the teardown manifest")
			}
			current, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
				windowsManagedHooksRuntimeSelectorOptions(target, opts.HookBinary),
			)
			if err != nil {
				return err
			}
			if current.CAS != expected.CAS ||
				current.Existed != expected.Existed ||
				current.TargetSHA256 != expected.TargetSHA256 ||
				!bytes.Equal(current.Target, expected.Target) {
				return fmt.Errorf(
					"managed runtime selector changed for %s target %s",
					expected.Connector,
					expected.TargetSID,
				)
			}
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
	[]enterprisehooks.WindowsCursorManagedRuntimeTarget,
	error,
) {
	targets := make([]windowsManagedHooksTeardownTarget, 0, len(manifest.Targets))
	claude := make([]string, 0, len(manifest.Targets))
	codex := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(manifest.Targets))
	cursor := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		sid, err := windows.StringToSid(strings.TrimSpace(target.SID))
		if err != nil || sid == nil {
			return nil, nil, nil, nil, fmt.Errorf("invalid managed-hook teardown SID %q", target.SID)
		}
		connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
		if connectorName != "claudecode" && connectorName != "codex" && connectorName != "cursor" {
			return nil, nil, nil, nil, fmt.Errorf(
				"managed-hook teardown does not support connector %q",
				target.Connector,
			)
		}
		dataDir := filepath.Join(filepath.Clean(target.UserHome), ".defenseclaw")
		if configured := strings.TrimSpace(target.DataDir); configured != "" {
			configured, err = filepath.Abs(configured)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			configured = filepath.Clean(configured)
			if !sameWindowsEnterprisePathCLI(configured, dataDir) {
				return nil, nil, nil, nil, fmt.Errorf(
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
		case "cursor":
			cursor = append(cursor, enterprisehooks.WindowsCursorManagedRuntimeTarget{
				SID: row.SID, DataDir: row.DataDir,
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
	sort.Slice(cursor, func(i, j int) bool { return cursor[i].SID < cursor[j].SID })
	return targets, claude, codex, cursor, nil
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
	if len(journal.SelectorTargets) != len(identity.Targets) {
		return errors.New("managed-hook teardown journal selector target set changed")
	}
	for index, target := range identity.Targets {
		snapshot := journal.SelectorTargets[index]
		digest := sha256.Sum256(snapshot.Target)
		targetDigest := "sha256:" + hex.EncodeToString(digest[:])
		if snapshot.SchemaVersion != 1 ||
			snapshot.Connector != target.Connector ||
			snapshot.TargetSID != target.SID ||
			!snapshot.Existed || !snapshot.CAS.Exists ||
			len(snapshot.Target) == 0 ||
			len(snapshot.Target) > windowsManagedHooksTeardownJournalMax ||
			snapshot.TargetSHA256 != targetDigest ||
			snapshot.CAS.TargetSHA256 != targetDigest ||
			!windowsManagedHooksValidGenerationID(snapshot.CAS.GenerationID) ||
			!windowsManagedHooksValidSHA256(snapshot.CAS.BundleSHA256) {
			return errors.New("managed-hook teardown journal contains an invalid selector snapshot")
		}
	}
	allowedClaudeTargets := make([]string, 0, len(identity.Targets))
	for _, target := range identity.Targets {
		if target.Connector == "claudecode" {
			allowedClaudeTargets = append(allowedClaudeTargets, target.SID)
		}
	}
	if _, err := windowsManagedHooksPartialClaudeTargets(
		allowedClaudeTargets,
		journal.ClaudeTargetSIDs,
		len(journal.ClaudeTargetSIDs) != 0,
	); err != nil {
		return err
	}
	if journal.Claude.PolicyExisted != journal.Claude.StateExisted ||
		len(journal.Claude.Policy) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Claude.State) > windowsManagedHooksTeardownJournalMax ||
		(journal.Claude.PolicyExisted != (len(journal.ClaudeTargetSIDs) != 0)) {
		return errors.New("managed-hook teardown journal contains an invalid Claude snapshot")
	}
	allowedCursorTargets := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(identity.Targets))
	for _, target := range identity.Targets {
		if target.Connector == "cursor" {
			allowedCursorTargets = append(allowedCursorTargets, enterprisehooks.WindowsCursorManagedRuntimeTarget{
				SID: target.SID, DataDir: target.DataDir,
			})
		}
	}
	if _, err := windowsManagedHooksPartialCursorTargets(
		allowedCursorTargets,
		journal.CursorTargets,
		len(journal.CursorTargets) != 0,
	); err != nil {
		return err
	}
	cursorSnapshotActive := journal.Cursor.PolicyActive
	if journal.Cursor.StateExisted != cursorSnapshotActive ||
		journal.Cursor.ReceiptExisted != cursorSnapshotActive ||
		(cursorSnapshotActive && (!journal.Cursor.AdapterExisted || !journal.Cursor.HooksExisted)) ||
		len(journal.Cursor.Hooks) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Cursor.Adapter) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Cursor.State) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Cursor.Receipt) > windowsManagedHooksTeardownJournalMax ||
		(journal.Cursor.HooksExisted != (journal.Cursor.HooksSecurityDescriptor != "" && journal.Cursor.HooksAttributes != 0)) ||
		(journal.Cursor.AdapterExisted != (journal.Cursor.AdapterSecurityDescriptor != "" && journal.Cursor.AdapterAttributes != 0)) ||
		(journal.Cursor.StateExisted != (journal.Cursor.StateSecurityDescriptor != "" && journal.Cursor.StateAttributes != 0)) ||
		(journal.Cursor.ReceiptExisted != (journal.Cursor.ReceiptSecurityDescriptor != "" && journal.Cursor.ReceiptAttributes != 0)) ||
		(cursorSnapshotActive != (len(journal.CursorTargets) != 0)) {
		return errors.New("managed-hook teardown journal contains an invalid Cursor snapshot")
	}
	return nil
}

func windowsManagedHooksValidGenerationID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func windowsManagedHooksValidSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(value, "sha256:") ||
		value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
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
