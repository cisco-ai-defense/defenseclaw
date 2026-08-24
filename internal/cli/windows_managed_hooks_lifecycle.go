// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

const (
	windowsManagedHooksLifecycleSchema         = 4
	windowsManagedHooksLifecycleLegacySchema   = 3
	windowsManagedHooksLifecycleJournalMax     = 32 << 20
	windowsManagedHooksLifecycleJournalFile    = "managed-hooks-lifecycle-journal.json"
	windowsManagedHooksLifecycleRecoverySchema = 1
	windowsManagedHooksLifecycleRecoveryLeaf   = "managed-hooks-lifecycle-journal.v3.quarantine"
	windowsManagedHooksLifecycleSelectorLeaf   = ".defenseclaw-managed-runtime-selector.state"
)

type windowsManagedHooksLifecycleJournal struct {
	SchemaVersion         int                                                        `json:"schema_version"`
	TransactionID         string                                                     `json:"transaction_id,omitempty"`
	Phase                 string                                                     `json:"phase"`
	ManifestPath          string                                                     `json:"manifest_path"`
	ManifestFingerprint   string                                                     `json:"manifest_fingerprint"`
	HookBinary            string                                                     `json:"hook_binary"`
	GatewayAddr           string                                                     `json:"gateway_addr"`
	GatewayServiceName    string                                                     `json:"gateway_service_name"`
	Targets               []windowsManagedHooksTeardownTarget                        `json:"targets"`
	PriorClaudeTargetSIDs []string                                                   `json:"prior_claude_target_sids"`
	Claude                enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot `json:"claude"`
	PriorCursorTargets    []enterprisehooks.WindowsCursorManagedRuntimeTarget        `json:"prior_cursor_targets"`
	Cursor                enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot `json:"cursor"`
	RuntimeSelectors      []enterprisehooks.WindowsManagedRuntimeSelectorSnapshot    `json:"runtime_selectors"`
}

type windowsManagedHooksLifecycleReport struct {
	SchemaVersion         int    `json:"schema_version"`
	Action                string `json:"action"`
	OK                    bool   `json:"ok"`
	JournalPath           string `json:"journal_path,omitempty"`
	TransactionID         string `json:"transaction_id,omitempty"`
	QuarantinePath        string `json:"quarantine_path,omitempty"`
	Adopted               bool   `json:"adopted,omitempty"`
	LegacyActivationState string `json:"legacy_activation_state,omitempty"`
	Phase                 string `json:"phase,omitempty"`
	Error                 string `json:"error,omitempty"`
}

type windowsManagedHooksLifecycleContext struct {
	opts             connector.WindowsCodexMachineRequirementsOptions
	manifestPath     string
	journalPath      string
	pendingPath      string
	deploymentPath   string
	transactionsPath string
	gatewayPath      string
	runtimePath      string
	targets          []windowsManagedHooksTeardownTarget
	claudeTargets    []string
	cursorTargets    []enterprisehooks.WindowsCursorManagedRuntimeTarget
	fingerprint      string
}

type windowsManagedHooksLifecyclePending struct {
	SchemaVersion int    `json:"schema_version"`
	Snapshot      string `json:"snapshot"`
	CreatedAt     string `json:"created_at"`
}

type windowsManagedHooksLifecycleSnapshot struct {
	SchemaVersion int                                        `json:"schema_version"`
	ID            string                                     `json:"id"`
	Directory     string                                     `json:"directory"`
	Files         []windowsManagedHooksLifecycleSnapshotFile `json:"files"`
	Recovery      json.RawMessage                            `json:"managed_hooks_lifecycle_recovery"`
}

type windowsManagedHooksLifecycleSnapshotFile struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Backup  string `json:"backup"`
}

type windowsManagedHooksLifecycleTransaction struct {
	ID        string
	Directory string
	Snapshot  windowsManagedHooksLifecycleSnapshot
}

type windowsManagedHooksLifecycleRecoveryBinding struct {
	SchemaVersion            int    `json:"schema_version"`
	TransactionID            string `json:"transaction_id"`
	State                    string `json:"state"`
	JournalPath              string `json:"journal_path"`
	JournalSHA256            string `json:"journal_sha256"`
	JournalFileIdentity      string `json:"journal_file_identity"`
	JournalSchemaVersion     int    `json:"journal_schema_version"`
	JournalPhase             string `json:"journal_phase"`
	ManifestSHA256           string `json:"manifest_sha256"`
	OldGatewaySHA256         string `json:"old_gateway_sha256"`
	ReplacementGatewaySHA256 string `json:"replacement_gateway_sha256"`
	QuarantinePath           string `json:"quarantine_path"`
}

type windowsManagedHooksLifecycleFileRenameInfo struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

type windowsManagedHooksClaudeLifecycleCapture struct {
	opts     enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions
	snapshot enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot
}

func newWindowsManagedHooksLifecycleCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "managed-hooks-lifecycle-snapshot",
		Short:  "Transactionally snapshot managed machine-hook enrollment",
		Hidden: true,
	}
	for _, action := range []string{
		"capture", "classify-activation", "restore", "retire", "retire-committed",
	} {
		action := action
		var jsonOutput bool
		child := &cobra.Command{
			Use:          action,
			Short:        action + " the managed machine-hook lifecycle snapshot",
			Hidden:       true,
			Args:         cobra.NoArgs,
			SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) error {
				report, err := runWindowsManagedHooksLifecycle(action)
				if jsonOutput {
					if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); encodeErr != nil {
						if err == nil {
							return encodeErr
						}
						return fmt.Errorf(
							"managed-hook lifecycle snapshot %s failed and its JSON report could not be encoded",
							action,
						)
					}
				} else if err == nil {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"Windows managed-hook lifecycle snapshot %s: %s\n",
						action,
						report.Phase,
					)
				}
				if err != nil {
					return fmt.Errorf("managed-hook lifecycle snapshot %s failed", action)
				}
				return nil
			},
		}
		child.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
		command.AddCommand(child)
	}
	return command
}

func runWindowsManagedHooksLifecycle(
	action string,
) (windowsManagedHooksLifecycleReport, error) {
	report := windowsManagedHooksLifecycleReport{
		SchemaVersion: windowsManagedHooksLifecycleSchema,
		Action:        action,
	}
	fail := func(err error) (windowsManagedHooksLifecycleReport, error) {
		report.OK = false
		report.Error = err.Error()
		return report, err
	}
	if action != "capture" && action != "restore" && action != "retire" &&
		action != "retire-committed" && action != "classify-activation" {
		return fail(fmt.Errorf("unsupported managed-hook lifecycle snapshot action %q", action))
	}
	if err := enterpriseHooksNativePlatformPreflight(); err != nil {
		return fail(err)
	}
	ctx, err := resolveWindowsManagedHooksLifecycleContext()
	if err != nil {
		return fail(err)
	}
	report.JournalPath = ctx.journalPath
	pending, err := readWindowsManagedHooksLifecycleTransaction(ctx)
	if err != nil {
		return fail(err)
	}
	pendingExists := pending != nil
	if action != "retire" && !pendingExists {
		return fail(errors.New(
			"managed-hook lifecycle snapshot requires an authenticated pending lifecycle transaction",
		))
	}
	if action == "retire-committed" {
		report, err = retireCommittedWindowsManagedHooksLifecycle(ctx, *pending, report)
		if err != nil {
			return fail(err)
		}
		return report, nil
	}
	if action == "classify-activation" {
		manifestSHA256, err := hashWindowsManagedHooksLifecycleTrustedFile(
			ctx.manifestPath,
			windowsManagedHooksLifecycleJournalMax,
			"Windows enterprise hook target manifest",
		)
		if err != nil {
			return fail(err)
		}
		state, err := classifyLegacyWindowsManagedHooksActivation(ctx, manifestSHA256)
		if err != nil {
			return fail(err)
		}
		report.OK = true
		report.TransactionID = pending.ID
		report.LegacyActivationState = state
		report.Phase = "classified"
		return report, nil
	}

	transactionID := ""
	if pending != nil {
		transactionID = pending.ID
	} else if action == "retire" {
		if _, statErr := os.Lstat(ctx.journalPath); errors.Is(statErr, os.ErrNotExist) {
			transactionID = ""
		} else if statErr != nil {
			return fail(statErr)
		} else {
			transactionID, err = windowsManagedHooksLifecycleCommittedTransactionID(ctx)
			if err != nil {
				return fail(err)
			}
		}
	}
	report.TransactionID = transactionID

	identity := windowsManagedHooksLifecycleJournal{
		SchemaVersion:       windowsManagedHooksLifecycleSchema,
		TransactionID:       transactionID,
		ManifestPath:        ctx.manifestPath,
		ManifestFingerprint: ctx.fingerprint,
		HookBinary:          ctx.opts.HookBinary,
		GatewayAddr:         ctx.opts.GatewayAddr,
		GatewayServiceName:  ctx.opts.GatewayServiceName,
		Targets:             ctx.targets,
	}
	switch action {
	case "capture":
		if _, err := os.Lstat(ctx.journalPath); err == nil {
			return fail(errors.New("managed-hook lifecycle snapshot journal already exists"))
		} else if !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
		current, active, err := enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
		if err != nil {
			return fail(err)
		}
		prior, err := windowsManagedHooksPartialClaudeTargets(
			ctx.claudeTargets,
			current,
			active,
		)
		if err != nil {
			return fail(err)
		}
		priorOpts := windowsManagedHooksClaudeOptions(ctx.opts, prior)
		snapshot, err := enterprisehooks.CaptureWindowsClaudeManagedPolicySnapshot(priorOpts)
		if err != nil {
			return fail(err)
		}
		currentCursor, cursorActive, err := enterprisehooks.ReadWindowsCursorManagedPolicyTargets()
		if err != nil {
			return fail(err)
		}
		priorCursor, err := windowsManagedHooksPartialCursorTargets(
			ctx.cursorTargets,
			currentCursor,
			cursorActive,
		)
		if err != nil {
			return fail(err)
		}
		cursorSnapshot, err := enterprisehooks.CaptureWindowsCursorManagedPolicySnapshot(
			windowsManagedHooksCursorOptions(ctx.opts, priorCursor),
		)
		if err != nil {
			return fail(err)
		}
		runtimeSelectors, err := captureWindowsManagedHooksLifecycleSelectors()
		if err != nil {
			return fail(err)
		}
		journal := identity
		journal.Phase = "captured"
		journal.PriorClaudeTargetSIDs = prior
		journal.Claude = snapshot
		journal.PriorCursorTargets = priorCursor
		journal.Cursor = cursorSnapshot
		journal.RuntimeSelectors = runtimeSelectors
		if err := writeWindowsManagedHooksLifecycleJournal(ctx.journalPath, journal); err != nil {
			return fail(err)
		}
		report.Phase = journal.Phase
	case "restore":
		journal, err := readWindowsManagedHooksLifecycleJournal(ctx.journalPath)
		if err != nil {
			return fail(err)
		}
		if err := validateWindowsManagedHooksLifecycleJournal(journal, identity); err != nil {
			return fail(err)
		}
		if journal.Phase != "captured" && journal.Phase != "restored" {
			return fail(fmt.Errorf(
				"managed-hook lifecycle snapshot phase %q cannot be restored",
				journal.Phase,
			))
		}
		priorClaudeOpts := windowsManagedHooksPriorClaudeOptions(journal)
		currentSelectors, err := captureWindowsManagedHooksLifecycleSelectors()
		if err != nil {
			return fail(err)
		}
		if err := restoreWindowsManagedHooksLifecycleSelectors(
			journal.RuntimeSelectors,
			currentSelectors,
		); err != nil {
			return fail(err)
		}
		currentClaude, err := captureWindowsManagedHooksLifecycleClaude(ctx, journal)
		if err != nil {
			selectorErr := restoreWindowsManagedHooksLifecycleSelectors(
				currentSelectors,
				journal.RuntimeSelectors,
			)
			return fail(errors.Join(err, selectorErr))
		}
		if err := restoreWindowsManagedHooksLifecycleComposite(
			func() error {
				return enterprisehooks.RestoreWindowsClaudeManagedPolicySnapshot(
					priorClaudeOpts,
					currentClaude.opts,
					journal.Claude,
				)
			},
			func() error {
				return enterprisehooks.RestoreWindowsCursorManagedPolicySnapshot(
					windowsManagedHooksPriorCursorOptions(journal),
					windowsManagedHooksCursorOptions(ctx.opts, ctx.cursorTargets),
					journal.Cursor,
				)
			},
			func() error {
				return enterprisehooks.RestoreWindowsClaudeManagedPolicySnapshot(
					currentClaude.opts,
					priorClaudeOpts,
					currentClaude.snapshot,
				)
			},
		); err != nil {
			selectorErr := restoreWindowsManagedHooksLifecycleSelectors(
				currentSelectors,
				journal.RuntimeSelectors,
			)
			return fail(errors.Join(err, selectorErr))
		}
		journal.Phase = "restored"
		if err := writeWindowsManagedHooksLifecycleJournal(ctx.journalPath, journal); err != nil {
			return fail(err)
		}
		report.Phase = journal.Phase
	case "retire":
		journal, err := readWindowsManagedHooksLifecycleJournal(ctx.journalPath)
		if errors.Is(err, os.ErrNotExist) {
			if err := validateWindowsManagedHooksLifecycleRetirement(
				pendingExists,
				nil,
			); err != nil {
				return fail(err)
			}
			report.Phase = "absent"
			break
		}
		if err != nil {
			return fail(err)
		}
		if err := validateWindowsManagedHooksLifecycleJournal(journal, identity); err != nil {
			return fail(err)
		}
		if err := validateWindowsManagedHooksLifecycleRetirement(
			pendingExists,
			&journal,
		); err != nil {
			return fail(err)
		}
		if err := garbageCollectWindowsManagedHooksLifecycleGenerations(
			journal,
			ctx,
		); err != nil {
			return fail(err)
		}
		if err := os.Remove(ctx.journalPath); err != nil {
			return fail(err)
		}
		if _, err := os.Lstat(ctx.journalPath); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = errors.New("journal still exists")
			}
			return fail(fmt.Errorf("verify managed-hook lifecycle journal retirement: %w", err))
		}
		report.Phase = "retired"
	}
	report.OK = true
	return report, nil
}

func validateWindowsManagedHooksLifecycleRetirement(
	pending bool,
	journal *windowsManagedHooksLifecycleJournal,
) error {
	if journal == nil {
		if pending {
			return errors.New(
				"pending lifecycle transaction lost its managed-hook lifecycle snapshot",
			)
		}
		return nil
	}
	if journal.Phase != "captured" && journal.Phase != "restored" {
		return fmt.Errorf(
			"refusing to retire managed-hook lifecycle snapshot in invalid phase %q",
			journal.Phase,
		)
	}
	if pending && journal.Phase != "restored" {
		return fmt.Errorf(
			"refusing to retire pending managed-hook lifecycle snapshot in phase %q",
			journal.Phase,
		)
	}
	return nil
}

func resolveWindowsManagedHooksLifecycleContext() (
	windowsManagedHooksLifecycleContext,
	error,
) {
	var ctx windowsManagedHooksLifecycleContext
	// Capture is opened during a fresh Install before deployment metadata has
	// been committed, or while an authenticated uninstall tombstone is being
	// replaced. The lifecycle layout path still authenticates the exact binary,
	// manifest, config, roots, and service environment.
	opts, err := resolveWindowsCodexRequirementsLayout("lifecycle")
	if err != nil {
		return ctx, err
	}
	// Both lifecycle and teardown publish administrator-owned journals under
	// filepath.Join(stateRoot, "install"). Apply the same canonicalization the
	// teardown path applies before deriving that stateRoot, so a layout the
	// teardown command rejects cannot reach lifecycle journal publication.
	ownershipPath := opts.OwnershipPath
	installDir := filepath.Dir(ownershipPath)
	stateRoot := filepath.Dir(installDir)
	if ownershipPath == "" || !filepath.IsAbs(ownershipPath) ||
		strings.TrimSpace(ownershipPath) != ownershipPath ||
		filepath.Clean(ownershipPath) != ownershipPath ||
		!strings.EqualFold(filepath.Base(ownershipPath), "codex-requirements-ownership.json") ||
		!strings.EqualFold(filepath.Base(installDir), "install") ||
		stateRoot == installDir || stateRoot == filepath.Dir(stateRoot) {
		return ctx, errors.New("managed-hook lifecycle received a noncanonical protected ownership path")
	}
	runtimeDir, err := exactWindowsCodexLayoutEnv("DEFENSECLAW_HOME")
	if err != nil {
		return ctx, err
	}
	if !strings.EqualFold(filepath.Base(runtimeDir), "runtime") ||
		!sameWindowsEnterprisePathCLI(stateRoot, filepath.Dir(runtimeDir)) {
		return ctx, errors.New("managed-hook lifecycle snapshot does not match the protected state root")
	}
	if err := managed.ValidateTrustedRuntimeDir(
		stateRoot,
		"Windows enterprise managed-hook lifecycle state root",
	); err != nil {
		return ctx, err
	}
	manifestPath := filepath.Join(stateRoot, "hook-guardian", "targets.yaml")
	if err := managed.ValidateTrustedFilePath(
		manifestPath,
		"Windows enterprise hook target manifest",
	); err != nil {
		return ctx, err
	}
	manifest, err := enterprisehooks.LoadManifest(manifestPath)
	if err != nil {
		return ctx, err
	}
	targets, claudeTargets, _, cursorTargets, err := windowsManagedHooksTeardownTargets(manifest)
	if err != nil {
		return ctx, err
	}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(targets)
	if err != nil {
		return ctx, err
	}
	installState := filepath.Join(stateRoot, "install")
	transactionsPath := filepath.Join(installState, "transactions")
	ctx = windowsManagedHooksLifecycleContext{
		opts:             opts,
		manifestPath:     manifestPath,
		journalPath:      filepath.Join(installState, windowsManagedHooksLifecycleJournalFile),
		pendingPath:      filepath.Join(installState, "pending.json"),
		deploymentPath:   filepath.Join(installState, "deployment.json"),
		transactionsPath: transactionsPath,
		gatewayPath:      filepath.Join(opts.ManagedDir, "defenseclaw-gateway.exe"),
		runtimePath:      runtimeDir,
		targets:          targets,
		claudeTargets:    claudeTargets,
		cursorTargets:    cursorTargets,
		fingerprint:      fingerprint,
	}
	return ctx, nil
}

func readWindowsManagedHooksLifecycleTransaction(
	ctx windowsManagedHooksLifecycleContext,
) (*windowsManagedHooksLifecycleTransaction, error) {
	var pending windowsManagedHooksLifecyclePending
	exists, err := readWindowsManagedHooksLifecycleJSON(
		ctx.pendingPath,
		128<<10,
		"pending Windows enterprise lifecycle transaction",
		true,
		&pending,
	)
	if err != nil || !exists {
		return nil, err
	}
	_, createdAtErr := time.Parse(time.RFC3339Nano, pending.CreatedAt)
	if pending.SchemaVersion != 1 || createdAtErr != nil ||
		!filepath.IsAbs(pending.Snapshot) ||
		filepath.Clean(pending.Snapshot) != pending.Snapshot {
		return nil, errors.New("pending lifecycle transaction reference is invalid")
	}

	transactionDirectory := filepath.Dir(pending.Snapshot)
	transactionID := filepath.Base(transactionDirectory)
	if !validWindowsManagedHooksLifecycleTransactionID(transactionID) ||
		!sameWindowsEnterprisePathCLI(filepath.Dir(transactionDirectory), ctx.transactionsPath) ||
		!strings.EqualFold(filepath.Base(pending.Snapshot), "snapshot.json") {
		return nil, errors.New("pending lifecycle transaction snapshot path is noncanonical")
	}
	var snapshot windowsManagedHooksLifecycleSnapshot
	exists, err = readWindowsManagedHooksLifecycleJSON(
		pending.Snapshot,
		windowsManagedHooksLifecycleJournalMax,
		"Windows enterprise lifecycle transaction snapshot",
		false,
		&snapshot,
	)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("pending lifecycle transaction snapshot is missing")
	}
	if snapshot.SchemaVersion != 1 || snapshot.ID != transactionID ||
		!sameWindowsManagedHooksLifecycleCanonicalPath(
			snapshot.Directory,
			transactionDirectory,
		) {
		return nil, errors.New("pending lifecycle transaction snapshot identity is invalid")
	}
	return &windowsManagedHooksLifecycleTransaction{
		ID:        transactionID,
		Directory: transactionDirectory,
		Snapshot:  snapshot,
	}, nil
}

func readWindowsManagedHooksLifecycleJSON(
	path string,
	limit int64,
	label string,
	disallowUnknown bool,
	destination any,
) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > limit {
		return false, fmt.Errorf("%s is not a bounded regular non-link file", label)
	}
	if err := managed.ValidateTrustedFilePath(path, label); err != nil {
		return false, err
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	var before windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &before); err != nil {
		_ = file.Close()
		return false, err
	}
	if before.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		before.NumberOfLinks != 1 {
		_ = file.Close()
		return false, fmt.Errorf("%s is not a single-link no-follow regular file", label)
	}
	opened, statErr := file.Stat()
	body, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	var after windows.ByHandleFileInformation
	handleStatErr := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &after)
	closeErr := file.Close()
	if statErr != nil {
		return false, statErr
	}
	if readErr != nil {
		return false, readErr
	}
	if handleStatErr != nil {
		return false, handleStatErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if len(body) > int(limit) || !os.SameFile(info, opened) ||
		before.NumberOfLinks != after.NumberOfLinks || after.NumberOfLinks != 1 ||
		windowsManagedHooksLifecycleFileIdentity(before) !=
			windowsManagedHooksLifecycleFileIdentity(after) ||
		before.FileSizeHigh != after.FileSizeHigh || before.FileSizeLow != after.FileSizeLow {
		return false, fmt.Errorf("%s changed while it was read", label)
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, current) {
		return false, fmt.Errorf("%s path changed while it was read", label)
	}
	decoder := json.NewDecoder(bytes.NewReader(trimWindowsJSONBOM(body)))
	if disallowUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return false, fmt.Errorf("parse %s: %w", label, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("%s contains trailing JSON", label)
	}
	return true, nil
}

func windowsManagedHooksLifecycleCommittedTransactionID(
	ctx windowsManagedHooksLifecycleContext,
) (string, error) {
	metadata, exists, err := readWindowsCodexDeploymentMetadata(ctx.deploymentPath)
	if err != nil {
		return "", err
	}
	if !exists || metadata.Installed == nil || !*metadata.Installed ||
		metadata.ManagedHooksActivation == nil {
		return "", errors.New(
			"committed managed-hook lifecycle snapshot has no authenticated activation binding",
		)
	}
	activation := metadata.ManagedHooksActivation
	if activation.SchemaVersion != 1 ||
		!validWindowsManagedHooksLifecycleTransactionID(activation.DeploymentGenerationID) ||
		(activation.State != "never_activated" && activation.State != "activated") ||
		!validWindowsManagedHooksLifecycleHex(activation.ManifestSHA256, sha256.Size) ||
		activation.TargetCount != len(ctx.targets) {
		return "", errors.New("deployment managed-hook activation binding is invalid")
	}
	manifestSHA256, err := hashWindowsManagedHooksLifecycleTrustedFile(
		ctx.manifestPath,
		windowsManagedHooksLifecycleJournalMax,
		"Windows enterprise hook target manifest",
	)
	if err != nil {
		return "", err
	}
	if activation.ManifestSHA256 != manifestSHA256 {
		return "", errors.New(
			"deployment managed-hook activation binding does not match the protected manifest",
		)
	}
	return activation.DeploymentGenerationID, nil
}

func retireCommittedWindowsManagedHooksLifecycle(
	ctx windowsManagedHooksLifecycleContext,
	transaction windowsManagedHooksLifecycleTransaction,
	report windowsManagedHooksLifecycleReport,
) (windowsManagedHooksLifecycleReport, error) {
	var binding windowsManagedHooksLifecycleRecoveryBinding
	if len(transaction.Snapshot.Recovery) == 0 ||
		bytes.Equal(bytes.TrimSpace(transaction.Snapshot.Recovery), []byte("null")) {
		return report, errors.New(
			"pending lifecycle transaction has no committed-journal recovery binding",
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(transaction.Snapshot.Recovery))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return report, fmt.Errorf("parse committed-journal recovery binding: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return report, errors.New("committed-journal recovery binding contains trailing JSON")
	}
	if err := validateWindowsManagedHooksLifecycleRecoveryBinding(
		binding,
		ctx,
		transaction,
	); err != nil {
		return report, err
	}

	journalExists, err := windowsManagedHooksLifecyclePathExists(ctx.journalPath)
	if err != nil {
		return report, err
	}
	quarantineExists, err := windowsManagedHooksLifecyclePathExists(binding.QuarantinePath)
	if err != nil {
		return report, err
	}
	if journalExists == quarantineExists {
		if journalExists {
			return report, errors.New(
				"committed managed-hook lifecycle journal and its quarantine both exist",
			)
		}
		return report, errors.New(
			"committed managed-hook lifecycle journal and its quarantine are both missing",
		)
	}

	path := ctx.journalPath
	if quarantineExists {
		path = binding.QuarantinePath
	}
	file, body, fileIdentity, err := openWindowsManagedHooksLifecycleRecoveryJournal(path)
	if err != nil {
		return report, err
	}
	defer file.Close()
	if fileIdentity != binding.JournalFileIdentity ||
		windowsManagedHooksLifecycleSHA256(body) != binding.JournalSHA256 {
		return report, errors.New(
			"committed managed-hook lifecycle journal changed after its recovery binding",
		)
	}
	journal, err := decodeWindowsManagedHooksLifecycleJournal(body)
	if err != nil {
		return report, err
	}
	if err := validateLegacyWindowsManagedHooksLifecycleJournal(
		journal,
		ctx,
		transaction.ID,
	); err != nil {
		return report, err
	}
	if err := validateWindowsManagedHooksLifecycleRecoveryHashes(
		binding,
		ctx,
		transaction,
	); err != nil {
		return report, err
	}
	legacyActivationState, err := classifyLegacyWindowsManagedHooksActivation(
		ctx,
		binding.ManifestSHA256,
	)
	if err != nil {
		return report, err
	}
	if err := finalizeRetireCommittedWindowsManagedHooksLifecycle(
		journal,
		ctx,
		journalExists,
		func() error {
			parent, err := openWindowsManagedHooksLifecycleRecoveryDirectory(transaction.Directory)
			if err != nil {
				return err
			}
			defer parent.Close()
			if err := renameWindowsManagedHooksLifecycleRecoveryHandle(
				windows.Handle(file.Fd()),
				windows.Handle(parent.Fd()),
				filepath.Base(binding.QuarantinePath),
			); err != nil {
				return fmt.Errorf("quarantine committed managed-hook lifecycle journal: %w", err)
			}
			return validateWindowsManagedHooksLifecycleRecoveryRename(
				file,
				fileIdentity,
				ctx.journalPath,
				binding.QuarantinePath,
			)
		},
	); err != nil {
		return report, err
	}

	report.OK = true
	report.TransactionID = transaction.ID
	report.QuarantinePath = binding.QuarantinePath
	report.Adopted = true
	report.LegacyActivationState = legacyActivationState
	report.Phase = "adopted"
	return report, nil
}

var windowsManagedHooksLifecycleGenerationGC = enterprisehooks.GarbageCollectWindowsManagedRuntimeGenerations

func finalizeRetireCommittedWindowsManagedHooksLifecycle(
	journal windowsManagedHooksLifecycleJournal,
	ctx windowsManagedHooksLifecycleContext,
	journalExists bool,
	rename func() error,
) error {
	// The legacy journal is recovery authority for generation collection as
	// well as enrollment restoration. Complete the bounded, idempotent GC
	// before moving that authority out of its canonical path. Retrying after
	// either crash edge repeats GC safely before acknowledging adoption.
	if err := garbageCollectWindowsManagedHooksLifecycleGenerations(journal, ctx); err != nil {
		return err
	}
	if !journalExists {
		return nil
	}
	return rename()
}

func classifyLegacyWindowsManagedHooksActivation(
	ctx windowsManagedHooksLifecycleContext,
	manifestSHA256 string,
) (string, error) {
	activation, exists, err := loadEnterpriseHookGuardianActivation(ctx.runtimePath)
	if err != nil {
		return "", fmt.Errorf("classify legacy managed-hook activation: %w", err)
	}
	authorization, authorizationExists, err := loadEnterpriseHookGuardianAuthorization(
		ctx.runtimePath,
	)
	if err != nil {
		return "", fmt.Errorf("classify legacy managed-hook authorization: %w", err)
	}
	state, stateExists, err := loadEnterpriseHookGuardianState(ctx.runtimePath)
	if err != nil {
		return "", fmt.Errorf("classify legacy managed-hook state: %w", err)
	}
	if exists {
		if !authorizationExists || !stateExists {
			return "", errors.New(
				"protected Guardian activation is present without its exact state and authorization pair",
			)
		}
		if err := validateLegacyWindowsManagedHooksGuardianActivation(
			activation,
			authorization,
			state,
			ctx,
			manifestSHA256,
		); err != nil {
			return "", err
		}
		return windowsManagedHooksActivated, nil
	}
	if authorizationExists || stateExists {
		return "", errors.New(
			"Guardian state or authorization is present without an exact activation record",
		)
	}

	if err := validateLegacyWindowsManagedHooksClaudePreactivation(); err != nil {
		return "", err
	}
	codexRegistry, err := connector.ResolveWindowsCodexManagedRuntimeRegistry(
		ctx.opts.HookBinary,
	)
	if err != nil {
		return "", err
	}
	if codexRegistry.Active != ctx.opts.CodexTargetEnabled ||
		len(codexRegistry.Targets) != 0 {
		return "", errors.New(
			"legacy deployment has no Guardian activation but Codex enrollment is not the exact preactivation form",
		)
	}
	cursorTargets, cursorActive, err := enterprisehooks.ReadWindowsCursorManagedPolicyTargets()
	if err != nil {
		return "", err
	}
	if cursorActive || len(cursorTargets) != 0 {
		return "", errors.New(
			"legacy deployment has no Guardian activation but Cursor enrollment is not the exact preactivation form",
		)
	}
	selectorPaths, err := windowsManagedHooksLifecycleSelectorPaths(ctx)
	if err != nil {
		return "", err
	}
	for connectorName, selectorPath := range selectorPaths {
		if err := validateWindowsManagedHooksLifecycleSelectorAbsent(
			selectorPath,
			connectorName,
		); err == nil {
			continue
		} else if errors.Is(err, errWindowsManagedHooksLifecycleSelectorPresent) {
			return "", fmt.Errorf(
				"legacy deployment has no Guardian activation but %s runtime selector is present",
				connectorName,
			)
		} else {
			return "", err
		}
	}
	return windowsManagedHooksNeverActivated, nil
}

func validateLegacyWindowsManagedHooksClaudePreactivation() error {
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		return fmt.Errorf("resolve trusted Program Files for Claude classification: %w", err)
	}
	directory := filepath.Join(programFiles, "ClaudeCode", "managed-settings.d")
	for _, leaf := range []string{
		"90-defenseclaw.json",
		".defenseclaw-managed-hooks.state",
	} {
		path := filepath.Join(directory, leaf)
		if err := validateWindowsManagedHooksLifecycleSelectorAbsent(
			path,
			"Claude preactivation "+leaf,
		); err == nil {
			continue
		} else if errors.Is(err, errWindowsManagedHooksLifecycleSelectorPresent) {
			return errors.New(
				"legacy deployment has no Guardian activation but Claude enrollment is not the exact preactivation form",
			)
		} else {
			return err
		}
	}
	return nil
}

func windowsManagedHooksLifecycleSelectorPaths(
	ctx windowsManagedHooksLifecycleContext,
) (map[string]string, error) {
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		return nil, fmt.Errorf("resolve trusted Program Files for selector classification: %w", err)
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return nil, fmt.Errorf("resolve trusted ProgramData for selector classification: %w", err)
	}
	paths := map[string]string{
		"claudecode": filepath.Join(
			programFiles,
			"ClaudeCode",
			"managed-settings.d",
			windowsManagedHooksLifecycleSelectorLeaf,
		),
		"codex": filepath.Join(
			filepath.Dir(ctx.opts.RequirementsPath),
			windowsManagedHooksLifecycleSelectorLeaf,
		),
		"cursor": filepath.Join(
			programData,
			"Cursor",
			windowsManagedHooksLifecycleSelectorLeaf,
		),
	}
	for connectorName, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			filepath.Base(path) != windowsManagedHooksLifecycleSelectorLeaf {
			return nil, fmt.Errorf(
				"%s managed runtime selector classification path is noncanonical",
				connectorName,
			)
		}
	}
	return paths, nil
}

var errWindowsManagedHooksLifecycleSelectorPresent = errors.New(
	"managed runtime selector is present",
)

func validateWindowsManagedHooksLifecycleSelectorAbsent(path, connectorName string) error {
	if _, err := os.Lstat(path); err == nil {
		return errWindowsManagedHooksLifecycleSelectorPresent
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s managed runtime selector: %w", connectorName, err)
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			if parent == filepath.Dir(parent) {
				return fmt.Errorf("%s managed runtime selector has no existing trusted ancestor", connectorName)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s managed runtime selector parent: %w", connectorName, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s managed runtime selector parent is not a no-link directory", connectorName)
		}
		return managed.ValidateTrustedDirectoryAncestor(
			parent,
			connectorName+" managed runtime selector ancestor",
		)
	}
}

func validateLegacyWindowsManagedHooksGuardianActivation(
	activation enterpriseHookGuardianActivation,
	authorization enterpriseHookGuardianAuthorization,
	state enterpriseHookGuardianState,
	ctx windowsManagedHooksLifecycleContext,
	manifestSHA256 string,
) error {
	_, activationTimeErr := time.Parse(time.RFC3339Nano, activation.UpdatedAt)
	expected := make([]enterpriseHookReconcileRow, 0, len(ctx.targets))
	for _, target := range ctx.targets {
		expected = append(expected, enterpriseHookReconcileRow{
			SID:       target.SID,
			Connector: target.Connector,
			OK:        true,
		})
	}
	activationIssues := compareEnterpriseHookProtectedTargetSets(
		expected,
		activation.ProtectedTargets,
	)
	authorizationIssues := compareEnterpriseHookProtectedTargetSets(
		expected,
		authorization.ProtectedTargets,
	)
	stateIssues := compareEnterpriseHookProtectedTargetSets(expected, state.Results)
	if activation.Version != enterpriseHookGuardianActivationVersion ||
		!validEnterpriseHookHex(activation.ReconcileID, 16) ||
		authorization.Version != 1 || state.Version != 1 || activationTimeErr != nil ||
		!activation.OK || activation.FailureCount != 0 ||
		activation.SuccessCount != len(ctx.targets) ||
		activation.TargetCount != len(ctx.targets) ||
		len(activation.ProtectedTargets) != len(ctx.targets) ||
		!authorization.OK || authorization.FailureCount != 0 ||
		authorization.SuccessCount != len(ctx.targets) ||
		authorization.TargetCount != len(ctx.targets) ||
		len(authorization.ProtectedTargets) != len(ctx.targets) ||
		!state.OK || state.FailureCount != 0 ||
		state.SuccessCount != len(ctx.targets) || state.TargetCount != len(ctx.targets) ||
		len(state.Results) != len(ctx.targets) ||
		activation.UpdatedAt == "" || activation.UpdatedAt != authorization.UpdatedAt ||
		activation.UpdatedAt != state.UpdatedAt ||
		!sameEnterpriseHookPath(activation.Manifest, ctx.manifestPath) ||
		!sameEnterpriseHookPath(state.Manifest, ctx.manifestPath) ||
		activation.ManifestSHA256 != manifestSHA256 ||
		len(activationIssues) != 0 || len(authorizationIssues) != 0 ||
		len(stateIssues) != 0 {
		return errors.New(
			"protected Guardian activation does not exactly bind the legacy deployment manifest and authorization",
		)
	}
	return nil
}

func validateWindowsManagedHooksLifecycleRecoveryBinding(
	binding windowsManagedHooksLifecycleRecoveryBinding,
	ctx windowsManagedHooksLifecycleContext,
	transaction windowsManagedHooksLifecycleTransaction,
) error {
	expectedQuarantine := filepath.Join(
		transaction.Directory,
		windowsManagedHooksLifecycleRecoveryLeaf,
	)
	if binding.SchemaVersion != windowsManagedHooksLifecycleRecoverySchema ||
		binding.TransactionID != transaction.ID || binding.State != "recorded" ||
		binding.JournalSchemaVersion != windowsManagedHooksLifecycleLegacySchema ||
		binding.JournalPhase != "captured" ||
		!sameWindowsManagedHooksLifecycleCanonicalPath(binding.JournalPath, ctx.journalPath) ||
		!sameWindowsManagedHooksLifecycleCanonicalPath(binding.QuarantinePath, expectedQuarantine) ||
		!validWindowsManagedHooksLifecycleHex(binding.JournalSHA256, sha256.Size) ||
		!validWindowsManagedHooksLifecycleFileIdentity(binding.JournalFileIdentity) ||
		!validWindowsManagedHooksLifecycleHex(binding.ManifestSHA256, sha256.Size) ||
		!validWindowsManagedHooksLifecycleHex(binding.OldGatewaySHA256, sha256.Size) ||
		!validWindowsManagedHooksLifecycleHex(binding.ReplacementGatewaySHA256, sha256.Size) {
		return errors.New("committed-journal recovery binding is invalid")
	}
	return nil
}

func validateWindowsManagedHooksLifecycleRecoveryHashes(
	binding windowsManagedHooksLifecycleRecoveryBinding,
	ctx windowsManagedHooksLifecycleContext,
	transaction windowsManagedHooksLifecycleTransaction,
) error {
	manifestSHA256, err := hashWindowsManagedHooksLifecycleTrustedFile(
		ctx.manifestPath,
		windowsManagedHooksLifecycleJournalMax,
		"Windows enterprise hook target manifest",
	)
	if err != nil {
		return err
	}
	if manifestSHA256 != binding.ManifestSHA256 {
		return errors.New(
			"committed-journal recovery manifest changed after transaction binding",
		)
	}
	replacementSHA256, err := hashWindowsManagedHooksLifecycleTrustedFile(
		ctx.gatewayPath,
		1<<30,
		"replacement Windows enterprise gateway executable",
	)
	if err != nil {
		return err
	}
	if replacementSHA256 != binding.ReplacementGatewaySHA256 {
		return errors.New(
			"running gateway does not match the transaction-bound replacement helper",
		)
	}

	var gatewayPreimage *windowsManagedHooksLifecycleSnapshotFile
	for index := range transaction.Snapshot.Files {
		entry := &transaction.Snapshot.Files[index]
		if sameWindowsEnterprisePathCLI(entry.Path, ctx.gatewayPath) {
			if gatewayPreimage != nil {
				return errors.New("transaction snapshot contains duplicate gateway preimages")
			}
			gatewayPreimage = entry
		}
	}
	if gatewayPreimage == nil || !gatewayPreimage.Existed ||
		!sameWindowsManagedHooksLifecycleTransactionBackup(
			gatewayPreimage.Backup,
			transaction.Directory,
		) {
		return errors.New("transaction snapshot has no canonical prior gateway preimage")
	}
	oldSHA256, err := hashWindowsManagedHooksLifecycleTrustedFile(
		gatewayPreimage.Backup,
		1<<30,
		"prior Windows enterprise gateway transaction preimage",
	)
	if err != nil {
		return err
	}
	if oldSHA256 != binding.OldGatewaySHA256 {
		return errors.New("prior gateway preimage changed after transaction binding")
	}
	return nil
}

func validateLegacyWindowsManagedHooksLifecycleJournal(
	journal windowsManagedHooksLifecycleJournal,
	ctx windowsManagedHooksLifecycleContext,
	transactionID string,
) error {
	if journal.SchemaVersion != windowsManagedHooksLifecycleLegacySchema ||
		journal.TransactionID != "" || journal.Phase != "captured" {
		return errors.New("committed lifecycle recovery requires an exact captured schema-3 journal")
	}
	identity := windowsManagedHooksLifecycleJournal{
		SchemaVersion:       windowsManagedHooksLifecycleSchema,
		TransactionID:       transactionID,
		ManifestPath:        ctx.manifestPath,
		ManifestFingerprint: ctx.fingerprint,
		HookBinary:          ctx.opts.HookBinary,
		GatewayAddr:         ctx.opts.GatewayAddr,
		GatewayServiceName:  ctx.opts.GatewayServiceName,
		Targets:             ctx.targets,
	}
	upgraded := journal
	upgraded.SchemaVersion = windowsManagedHooksLifecycleSchema
	upgraded.TransactionID = transactionID
	if err := validateWindowsManagedHooksLifecycleJournal(upgraded, identity); err != nil {
		return fmt.Errorf("validate legacy committed managed-hook lifecycle journal: %w", err)
	}
	if journal.GatewayAddr != ctx.opts.GatewayAddr ||
		journal.ManifestFingerprint != ctx.fingerprint ||
		len(journal.Targets) != len(ctx.targets) {
		return errors.New(
			"legacy committed managed-hook lifecycle journal does not match the current protected manifest",
		)
	}
	for index := range ctx.targets {
		if journal.Targets[index] != ctx.targets[index] {
			return errors.New(
				"legacy committed managed-hook lifecycle journal target identity changed",
			)
		}
	}
	return nil
}

func openWindowsManagedHooksLifecycleRecoveryJournal(
	path string,
) (*os.File, []byte, string, error) {
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, nil, "", err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|
			windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	if err != nil {
		return nil, nil, "", err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, "", errors.New("wrap committed lifecycle journal handle")
	}
	fail := func(err error) (*os.File, []byte, string, error) {
		_ = file.Close()
		return nil, nil, "", err
	}
	var before windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &before); err != nil {
		return fail(err)
	}
	if before.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		before.NumberOfLinks != 1 ||
		before.FileSizeHigh != 0 || before.FileSizeLow > windowsManagedHooksLifecycleJournalMax {
		return fail(errors.New(
			"committed lifecycle journal is not a bounded single-link no-follow regular file",
		))
	}
	if err := managed.ValidateTrustedFilePath(path, "committed managed-hook lifecycle journal"); err != nil {
		return fail(err)
	}
	body, err := io.ReadAll(io.LimitReader(file, windowsManagedHooksLifecycleJournalMax+1))
	if err != nil {
		return fail(err)
	}
	if len(body) > windowsManagedHooksLifecycleJournalMax {
		return fail(errors.New("committed managed-hook lifecycle journal exceeds its bound"))
	}
	var after windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &after); err != nil {
		return fail(err)
	}
	if windowsManagedHooksLifecycleFileIdentity(before) !=
		windowsManagedHooksLifecycleFileIdentity(after) ||
		after.NumberOfLinks != 1 || before.FileSizeHigh != after.FileSizeHigh ||
		before.FileSizeLow != after.FileSizeLow {
		return fail(errors.New("committed lifecycle journal changed while it was read"))
	}
	return file, body, windowsManagedHooksLifecycleFileIdentity(after), nil
}

func openWindowsManagedHooksLifecycleRecoveryDirectory(path string) (*os.File, error) {
	if err := managed.ValidateTrustedRuntimeDir(
		path,
		"committed lifecycle recovery transaction directory",
	); err != nil {
		return nil, err
	}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		// FILE_WRITE_DATA is FILE_ADD_FILE when the handle names a directory.
		windows.FILE_LIST_DIRECTORY|windows.FILE_WRITE_DATA|windows.FILE_READ_ATTRIBUTES|
			windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("committed lifecycle recovery parent is not a no-follow directory")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap committed lifecycle recovery directory handle")
	}
	return file, nil
}

func renameWindowsManagedHooksLifecycleRecoveryHandle(
	handle windows.Handle,
	parent windows.Handle,
	leaf string,
) error {
	name, err := windows.UTF16FromString(leaf)
	if err != nil || len(name) < 2 {
		return windows.ERROR_INVALID_NAME
	}
	name = name[:len(name)-1]
	var layout windowsManagedHooksLifecycleFileRenameInfo
	buffer := make([]byte, int(unsafe.Offsetof(layout.FileName))+len(name)*2)
	info := (*windowsManagedHooksLifecycleFileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.RootDirectory = parent
	info.FileNameLength = uint32(len(name) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	var status windows.IO_STATUS_BLOCK
	err = windows.NtSetInformationFile(
		handle,
		&status,
		&buffer[0],
		uint32(len(buffer)),
		windows.FileRenameInformation,
	)
	runtime.KeepAlive(buffer)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) ||
			errors.Is(err, windows.STATUS_OBJECT_NAME_EXISTS) {
			return windows.ERROR_ALREADY_EXISTS
		}
		var statusErr windows.NTStatus
		if errors.As(err, &statusErr) {
			return statusErr.Errno()
		}
		return err
	}
	// The source handle is write-through. Flush after the handle-bound rename
	// so NTFS has a durability barrier for the namespace update before
	// PowerShell persists the adopted recovery receipt.
	return windows.FlushFileBuffers(handle)
}

func validateWindowsManagedHooksLifecycleRecoveryRename(
	file *os.File,
	expectedIdentity string,
	sourcePath string,
	quarantinePath string,
) error {
	if _, err := os.Lstat(sourcePath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = errors.New("source still exists")
		}
		return fmt.Errorf("verify committed lifecycle journal source retirement: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	quarantined, err := os.Lstat(quarantinePath)
	if err != nil {
		return err
	}
	if !quarantined.Mode().IsRegular() || quarantined.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, quarantined) {
		return errors.New("committed lifecycle quarantine path changed file identity")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 || windowsManagedHooksLifecycleFileIdentity(info) != expectedIdentity {
		return errors.New("committed lifecycle journal identity changed during quarantine")
	}
	return managed.ValidateTrustedFilePath(
		quarantinePath,
		"quarantined committed managed-hook lifecycle journal",
	)
}

func windowsManagedHooksLifecyclePathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func hashWindowsManagedHooksLifecycleTrustedFile(
	path string,
	limit int64,
	label string,
) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > limit {
		return "", fmt.Errorf("%s is not a bounded regular non-link file", label)
	}
	if err := managed.ValidateTrustedFilePath(path, label); err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	var before windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &before); err != nil {
		_ = file.Close()
		return "", err
	}
	if before.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		before.NumberOfLinks != 1 {
		_ = file.Close()
		return "", fmt.Errorf("%s is not a single-link no-follow regular file", label)
	}
	opened, statErr := file.Stat()
	hash := sha256.New()
	_, hashErr := io.Copy(hash, io.LimitReader(file, limit+1))
	var after windows.ByHandleFileInformation
	handleStatErr := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &after)
	closeErr := file.Close()
	if statErr != nil {
		return "", statErr
	}
	if hashErr != nil {
		return "", hashErr
	}
	if handleStatErr != nil {
		return "", handleStatErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if !os.SameFile(info, opened) || opened.Size() > limit ||
		before.NumberOfLinks != after.NumberOfLinks || after.NumberOfLinks != 1 ||
		windowsManagedHooksLifecycleFileIdentity(before) !=
			windowsManagedHooksLifecycleFileIdentity(after) ||
		before.FileSizeHigh != after.FileSizeHigh || before.FileSizeLow != after.FileSizeLow {
		return "", fmt.Errorf("%s changed while it was hashed", label)
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, current) {
		return "", fmt.Errorf("%s path changed while it was hashed", label)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func decodeWindowsManagedHooksLifecycleJournal(
	body []byte,
) (windowsManagedHooksLifecycleJournal, error) {
	var journal windowsManagedHooksLifecycleJournal
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return journal, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return journal, errors.New("managed-hook lifecycle journal contains trailing JSON")
		}
		return journal, err
	}
	return journal, nil
}

func windowsManagedHooksLifecycleSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return fmt.Sprintf("%x", digest[:])
}

func validWindowsManagedHooksLifecycleHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validWindowsManagedHooksLifecycleFileIdentity(value string) bool {
	if len(value) != 25 || value[8] != ':' {
		return false
	}
	return validWindowsManagedHooksLifecycleHex(value[:8], 4) &&
		validWindowsManagedHooksLifecycleHex(value[9:], 8)
}

func windowsManagedHooksLifecycleFileIdentity(
	info windows.ByHandleFileInformation,
) string {
	return fmt.Sprintf(
		"%08x:%08x%08x",
		info.VolumeSerialNumber,
		info.FileIndexHigh,
		info.FileIndexLow,
	)
}

func sameWindowsManagedHooksLifecycleCanonicalPath(value, expected string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value &&
		sameWindowsEnterprisePathCLI(value, expected)
}

func sameWindowsManagedHooksLifecycleTransactionBackup(path, directory string) bool {
	if !sameWindowsManagedHooksLifecycleCanonicalPath(
		filepath.Dir(path),
		directory,
	) {
		return false
	}
	leaf := filepath.Base(path)
	if !strings.HasPrefix(leaf, "file-") || !strings.HasSuffix(leaf, ".bak") {
		return false
	}
	digits := strings.TrimSuffix(strings.TrimPrefix(leaf, "file-"), ".bak")
	if len(digits) < 2 || len(digits) > 6 {
		return false
	}
	for _, char := range digits {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

var windowsManagedHooksLifecycleSelectorConnectors = [...]string{
	"claudecode",
	"codex",
	"cursor",
}

var (
	windowsManagedHooksLifecycleSelectorCapture = enterprisehooks.CaptureWindowsManagedRuntimeSelector
	windowsManagedHooksLifecycleSelectorRestore = enterprisehooks.RestoreWindowsManagedRuntimeSelectorCAS
)

func captureWindowsManagedHooksLifecycleSelectors() (
	[]enterprisehooks.WindowsManagedRuntimeSelectorSnapshot,
	error,
) {
	snapshots := make(
		[]enterprisehooks.WindowsManagedRuntimeSelectorSnapshot,
		0,
		len(windowsManagedHooksLifecycleSelectorConnectors),
	)
	for _, connectorName := range windowsManagedHooksLifecycleSelectorConnectors {
		snapshot, err := windowsManagedHooksLifecycleSelectorCapture(
			connectorName,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"capture %s managed runtime selector: %w",
				connectorName,
				err,
			)
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func validateWindowsManagedHooksLifecycleSelectors(
	snapshots []enterprisehooks.WindowsManagedRuntimeSelectorSnapshot,
) error {
	if len(snapshots) != len(windowsManagedHooksLifecycleSelectorConnectors) {
		return fmt.Errorf(
			"managed-hook lifecycle journal contains %d runtime selectors; expected %d",
			len(snapshots),
			len(windowsManagedHooksLifecycleSelectorConnectors),
		)
	}
	for index, connectorName := range windowsManagedHooksLifecycleSelectorConnectors {
		snapshot := snapshots[index]
		if snapshot.SchemaVersion != 1 || snapshot.Connector != connectorName ||
			snapshot.Existed != snapshot.CAS.Exists ||
			len(snapshot.Selector) > windowsManagedHooksLifecycleJournalMax {
			return fmt.Errorf(
				"managed-hook lifecycle journal contains an invalid %s runtime selector snapshot",
				connectorName,
			)
		}
		if snapshot.Existed {
			if len(snapshot.Selector) == 0 || snapshot.SelectorSHA256 == "" ||
				snapshot.CAS.SHA256 != snapshot.SelectorSHA256 {
				return fmt.Errorf(
					"managed-hook lifecycle journal contains an incomplete %s runtime selector snapshot",
					connectorName,
				)
			}
		} else if len(snapshot.Selector) != 0 || snapshot.SelectorSHA256 != "" ||
			snapshot.CAS.SHA256 != "" {
			return fmt.Errorf(
				"managed-hook lifecycle journal contains contradictory absent %s runtime selector state",
				connectorName,
			)
		}
	}
	return nil
}

func restoreWindowsManagedHooksLifecycleSelectors(
	desired []enterprisehooks.WindowsManagedRuntimeSelectorSnapshot,
	current []enterprisehooks.WindowsManagedRuntimeSelectorSnapshot,
) error {
	if err := validateWindowsManagedHooksLifecycleSelectors(desired); err != nil {
		return err
	}
	if err := validateWindowsManagedHooksLifecycleSelectors(current); err != nil {
		return err
	}
	restored := 0
	for index := range desired {
		err := windowsManagedHooksLifecycleSelectorRestore(
			enterprisehooks.WindowsManagedRuntimeSelectorFullRestoreOptions{
				Snapshot:        desired[index],
				ExpectedCurrent: current[index].CAS,
			},
		)
		if err == nil {
			restored++
			continue
		}
		failures := []error{fmt.Errorf(
			"restore %s managed runtime selector: %w",
			desired[index].Connector,
			err,
		)}
		for rollbackIndex := restored - 1; rollbackIndex >= 0; rollbackIndex-- {
			rollbackErr := windowsManagedHooksLifecycleSelectorRestore(
				enterprisehooks.WindowsManagedRuntimeSelectorFullRestoreOptions{
					Snapshot:        current[rollbackIndex],
					ExpectedCurrent: desired[rollbackIndex].CAS,
				},
			)
			if rollbackErr != nil {
				failures = append(failures, fmt.Errorf(
					"restore current %s selector after composite failure: %w",
					current[rollbackIndex].Connector,
					rollbackErr,
				))
			}
		}
		return errors.Join(failures...)
	}
	return nil
}

func garbageCollectWindowsManagedHooksLifecycleGenerations(
	journal windowsManagedHooksLifecycleJournal,
	ctx windowsManagedHooksLifecycleContext,
) error {
	type cleanupTarget struct {
		connector      string
		sid            string
		dataDir        string
		hookExecutable string
	}
	targets := make(map[string]cleanupTarget, len(journal.Targets)+len(ctx.targets))
	add := func(target windowsManagedHooksTeardownTarget, hookExecutable string) {
		key := target.Connector + "\x00" + strings.ToUpper(target.SID)
		targets[key] = cleanupTarget{
			connector:      target.Connector,
			sid:            target.SID,
			dataDir:        target.DataDir,
			hookExecutable: hookExecutable,
		}
	}
	if journal.Phase == "restored" {
		for _, target := range ctx.targets {
			add(target, ctx.opts.HookBinary)
		}
		for _, target := range journal.Targets {
			add(target, journal.HookBinary)
		}
	} else {
		for _, target := range journal.Targets {
			add(target, journal.HookBinary)
		}
		for _, target := range ctx.targets {
			add(target, ctx.opts.HookBinary)
		}
	}
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		target := targets[key]
		if _, err := windowsManagedHooksLifecycleGenerationGC(
			enterprisehooks.WindowsManagedRuntimeGenerationGCOptions{
				Connector:      target.connector,
				TargetSID:      target.sid,
				DataDir:        target.dataDir,
				HookExecutable: target.hookExecutable,
			},
		); err != nil {
			return fmt.Errorf(
				"retire %s managed runtime generations for SID %s: %w",
				target.connector,
				target.sid,
				err,
			)
		}
	}
	return nil
}

func windowsManagedHooksClaudeOptions(
	opts connector.WindowsCodexMachineRequirementsOptions,
	targets []string,
) enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions {
	return enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions{
		HookExecutable:     opts.HookBinary,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		TargetSIDs:         append([]string(nil), targets...),
	}
}

func windowsManagedHooksPriorClaudeOptions(
	journal windowsManagedHooksLifecycleJournal,
) enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions {
	return enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions{
		HookExecutable:     journal.HookBinary,
		GatewayAddr:        journal.GatewayAddr,
		GatewayServiceName: journal.GatewayServiceName,
		TargetSIDs:         append([]string(nil), journal.PriorClaudeTargetSIDs...),
	}
}

func captureWindowsManagedHooksLifecycleClaude(
	ctx windowsManagedHooksLifecycleContext,
	journal windowsManagedHooksLifecycleJournal,
) (windowsManagedHooksClaudeLifecycleCapture, error) {
	var result windowsManagedHooksClaudeLifecycleCapture
	current, active, err := enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
	if err != nil {
		return result, fmt.Errorf("capture current Claude lifecycle enrollment: %w", err)
	}
	type captureCandidate struct {
		opts    enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions
		allowed []string
	}
	candidates := []captureCandidate{
		{opts: enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions{
			HookExecutable:     journal.HookBinary,
			GatewayAddr:        journal.GatewayAddr,
			GatewayServiceName: journal.GatewayServiceName,
			TargetSIDs:         append([]string(nil), current...),
		}, allowed: journal.PriorClaudeTargetSIDs},
		{opts: windowsManagedHooksClaudeOptions(ctx.opts, current), allowed: ctx.claudeTargets},
	}
	var failures []error
	for _, candidate := range candidates {
		if _, subsetErr := windowsManagedHooksPartialClaudeTargets(
			candidate.allowed,
			current,
			active,
		); subsetErr != nil {
			failures = append(failures, subsetErr)
			continue
		}
		snapshot, captureErr := enterprisehooks.CaptureWindowsClaudeManagedPolicySnapshot(candidate.opts)
		if captureErr == nil {
			result.opts = candidate.opts
			result.snapshot = snapshot
			return result, nil
		}
		failures = append(failures, captureErr)
	}
	return result, fmt.Errorf(
		"capture current Claude lifecycle policy under journaled or staged identity: %w",
		errors.Join(failures...),
	)
}

func restoreWindowsManagedHooksLifecycleComposite(
	restoreClaude func() error,
	restoreCursor func() error,
	compensateClaude func() error,
) error {
	if err := restoreClaude(); err != nil {
		return err
	}
	if err := restoreCursor(); err != nil {
		if compensateErr := compensateClaude(); compensateErr != nil {
			return errors.Join(
				err,
				fmt.Errorf("restore current Claude policy after Cursor restore failure: %w", compensateErr),
			)
		}
		return err
	}
	return nil
}

func windowsManagedHooksCursorOptions(
	opts connector.WindowsCodexMachineRequirementsOptions,
	targets []enterprisehooks.WindowsCursorManagedRuntimeTarget,
) enterprisehooks.WindowsCursorManagedPolicyTeardownOptions {
	return enterprisehooks.WindowsCursorManagedPolicyTeardownOptions{
		HookExecutable:     opts.HookBinary,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		Targets:            append([]enterprisehooks.WindowsCursorManagedRuntimeTarget(nil), targets...),
	}
}

func windowsManagedHooksPriorCursorOptions(
	journal windowsManagedHooksLifecycleJournal,
) enterprisehooks.WindowsCursorManagedPolicyTeardownOptions {
	return enterprisehooks.WindowsCursorManagedPolicyTeardownOptions{
		HookExecutable:     journal.HookBinary,
		GatewayAddr:        journal.GatewayAddr,
		GatewayServiceName: journal.GatewayServiceName,
		Targets:            append([]enterprisehooks.WindowsCursorManagedRuntimeTarget(nil), journal.PriorCursorTargets...),
	}
}

func windowsManagedHooksPartialClaudeTargets(
	manifestTargets []string,
	currentTargets []string,
	active bool,
) ([]string, error) {
	if !active {
		if len(currentTargets) != 0 {
			return nil, errors.New("inactive Claude machine enrollment reported target SIDs")
		}
		return []string{}, nil
	}
	if len(currentTargets) == 0 || !sort.StringsAreSorted(currentTargets) {
		return nil, errors.New("active Claude machine enrollment has a noncanonical target set")
	}
	allowed := make(map[string]struct{}, len(manifestTargets))
	for _, sid := range manifestTargets {
		allowed[sid] = struct{}{}
	}
	prior := make([]string, 0, len(currentTargets))
	for index, sid := range currentTargets {
		if index > 0 && currentTargets[index-1] == sid {
			return nil, errors.New("active Claude machine enrollment contains a duplicate target SID")
		}
		if _, ok := allowed[sid]; !ok {
			return nil, fmt.Errorf(
				"Claude machine enrollment contains SID %s outside the protected teardown manifest",
				sid,
			)
		}
		prior = append(prior, sid)
	}
	return prior, nil
}

func windowsManagedHooksPartialCursorTargets(
	manifestTargets []enterprisehooks.WindowsCursorManagedRuntimeTarget,
	currentTargets []enterprisehooks.WindowsCursorManagedRuntimeTarget,
	active bool,
) ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, error) {
	if !active {
		if len(currentTargets) != 0 {
			return nil, errors.New("inactive Cursor machine enrollment reported targets")
		}
		return []enterprisehooks.WindowsCursorManagedRuntimeTarget{}, nil
	}
	if len(currentTargets) == 0 || !sort.SliceIsSorted(currentTargets, func(i, j int) bool {
		return currentTargets[i].SID < currentTargets[j].SID
	}) {
		return nil, errors.New("active Cursor machine enrollment has a noncanonical target set")
	}
	allowed := make(map[string]string, len(manifestTargets))
	for _, target := range manifestTargets {
		allowed[strings.ToUpper(target.SID)] = target.DataDir
	}
	prior := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(currentTargets))
	for index, target := range currentTargets {
		if index > 0 && strings.EqualFold(currentTargets[index-1].SID, target.SID) {
			return nil, errors.New("active Cursor machine enrollment contains a duplicate target SID")
		}
		dataDir, ok := allowed[strings.ToUpper(target.SID)]
		if !ok || !sameWindowsEnterprisePathCLI(dataDir, target.DataDir) {
			return nil, fmt.Errorf(
				"Cursor machine enrollment contains target %s outside the protected lifecycle manifest",
				target.SID,
			)
		}
		prior = append(prior, target)
	}
	return prior, nil
}

func validateWindowsManagedHooksLifecycleJournal(
	journal windowsManagedHooksLifecycleJournal,
	identity windowsManagedHooksLifecycleJournal,
) error {
	if journal.SchemaVersion != windowsManagedHooksLifecycleSchema ||
		!validWindowsManagedHooksLifecycleTransactionID(journal.TransactionID) ||
		journal.TransactionID != identity.TransactionID ||
		journal.ManifestPath != identity.ManifestPath ||
		journal.HookBinary != identity.HookBinary ||
		journal.GatewayServiceName != identity.GatewayServiceName {
		return errors.New("managed-hook lifecycle snapshot does not match the protected deployment")
	}
	canonicalGateway, err := connector.NormalizeWindowsManagedGatewayAddr(
		journal.GatewayAddr,
	)
	if err != nil || canonicalGateway != journal.GatewayAddr {
		return errors.New("managed-hook lifecycle snapshot gateway identity changed")
	}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(journal.Targets)
	if err != nil || fingerprint != journal.ManifestFingerprint {
		return errors.New("managed-hook lifecycle snapshot manifest identity changed")
	}
	priorAllowedClaudeTargets := make([]string, 0, len(journal.Targets))
	for _, target := range journal.Targets {
		if target.Connector == "claudecode" {
			priorAllowedClaudeTargets = append(priorAllowedClaudeTargets, target.SID)
		}
	}
	if _, err := windowsManagedHooksPartialClaudeTargets(
		priorAllowedClaudeTargets,
		journal.PriorClaudeTargetSIDs,
		len(journal.PriorClaudeTargetSIDs) != 0,
	); err != nil {
		return err
	}
	if journal.Claude.PolicyExisted != journal.Claude.StateExisted ||
		len(journal.Claude.Policy) > windowsManagedHooksLifecycleJournalMax ||
		len(journal.Claude.State) > windowsManagedHooksLifecycleJournalMax ||
		(journal.Claude.PolicyExisted != (len(journal.PriorClaudeTargetSIDs) != 0)) {
		return errors.New("managed-hook lifecycle journal contains an invalid Claude snapshot")
	}
	priorAllowedCursorTargets := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(journal.Targets))
	for _, target := range journal.Targets {
		if target.Connector == "cursor" {
			priorAllowedCursorTargets = append(priorAllowedCursorTargets, enterprisehooks.WindowsCursorManagedRuntimeTarget{
				SID: target.SID, DataDir: target.DataDir,
			})
		}
	}
	if _, err := windowsManagedHooksPartialCursorTargets(
		priorAllowedCursorTargets,
		journal.PriorCursorTargets,
		len(journal.PriorCursorTargets) != 0,
	); err != nil {
		return err
	}
	cursorActive := journal.Cursor.PolicyActive
	if journal.Cursor.StateExisted != cursorActive ||
		journal.Cursor.ReceiptExisted != cursorActive ||
		(cursorActive && (!journal.Cursor.HooksExisted || !journal.Cursor.AdapterExisted)) ||
		len(journal.Cursor.Hooks) > windowsManagedHooksLifecycleJournalMax ||
		len(journal.Cursor.Adapter) > windowsManagedHooksLifecycleJournalMax ||
		len(journal.Cursor.State) > windowsManagedHooksLifecycleJournalMax ||
		len(journal.Cursor.Receipt) > windowsManagedHooksLifecycleJournalMax ||
		(journal.Cursor.HooksExisted != (journal.Cursor.HooksSecurityDescriptor != "" && journal.Cursor.HooksAttributes != 0)) ||
		(journal.Cursor.AdapterExisted != (journal.Cursor.AdapterSecurityDescriptor != "" && journal.Cursor.AdapterAttributes != 0)) ||
		(journal.Cursor.StateExisted != (journal.Cursor.StateSecurityDescriptor != "" && journal.Cursor.StateAttributes != 0)) ||
		(journal.Cursor.ReceiptExisted != (journal.Cursor.ReceiptSecurityDescriptor != "" && journal.Cursor.ReceiptAttributes != 0)) ||
		(cursorActive != (len(journal.PriorCursorTargets) != 0)) {
		return errors.New("managed-hook lifecycle journal contains an invalid Cursor snapshot")
	}
	if err := validateWindowsManagedHooksLifecycleSelectors(
		journal.RuntimeSelectors,
	); err != nil {
		return err
	}
	return nil
}

func validWindowsManagedHooksLifecycleTransactionID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func readWindowsManagedHooksLifecycleJournal(
	path string,
) (windowsManagedHooksLifecycleJournal, error) {
	var journal windowsManagedHooksLifecycleJournal
	info, err := os.Lstat(path)
	if err != nil {
		return journal, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() > windowsManagedHooksLifecycleJournalMax {
		return journal, errors.New(
			"managed-hook lifecycle journal is not a bounded regular non-link file",
		)
	}
	if err := managed.ValidateTrustedFilePath(path, "managed-hook lifecycle journal"); err != nil {
		return journal, err
	}
	file, err := os.Open(path)
	if err != nil {
		return journal, err
	}
	decoder := json.NewDecoder(io.LimitReader(
		file,
		windowsManagedHooksLifecycleJournalMax+1,
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
			return journal, errors.New("managed-hook lifecycle journal contains trailing JSON")
		}
		return journal, err
	}
	if err := file.Close(); err != nil {
		return journal, err
	}
	return journal, nil
}

func writeWindowsManagedHooksLifecycleJournal(
	path string,
	journal windowsManagedHooksLifecycleJournal,
) error {
	body, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > windowsManagedHooksLifecycleJournalMax {
		return fmt.Errorf(
			"managed-hook lifecycle journal exceeds %d-byte limit",
			windowsManagedHooksLifecycleJournalMax,
		)
	}
	parent := filepath.Dir(path)
	if err := managed.ValidateTrustedRuntimeDir(
		parent,
		"managed-hook lifecycle journal parent",
	); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("managed-hook lifecycle journal is not a regular non-link file")
		}
		if err := managed.ValidateTrustedFilePath(path, "managed-hook lifecycle journal"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".managed-hooks-lifecycle-*")
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
		return errors.New("managed-hook lifecycle journal changed during publication")
	}
	return managed.ValidateTrustedFilePath(path, "managed-hook lifecycle journal")
}
