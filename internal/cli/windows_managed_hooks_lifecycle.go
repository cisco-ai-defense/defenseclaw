// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
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
	windowsManagedHooksLifecycleSchema      = 1
	windowsManagedHooksLifecycleJournalMax  = 4 << 20
	windowsManagedHooksLifecycleJournalFile = "managed-hooks-lifecycle-journal.json"
)

type windowsManagedHooksLifecycleJournal struct {
	SchemaVersion         int                                                        `json:"schema_version"`
	Phase                 string                                                     `json:"phase"`
	ManifestPath          string                                                     `json:"manifest_path"`
	ManifestFingerprint   string                                                     `json:"manifest_fingerprint"`
	HookBinary            string                                                     `json:"hook_binary"`
	GatewayAddr           string                                                     `json:"gateway_addr"`
	GatewayServiceName    string                                                     `json:"gateway_service_name"`
	Targets               []windowsManagedHooksTeardownTarget                        `json:"targets"`
	PriorClaudeTargetSIDs []string                                                   `json:"prior_claude_target_sids"`
	Claude                enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot `json:"claude"`
}

type windowsManagedHooksLifecycleReport struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	OK            bool   `json:"ok"`
	JournalPath   string `json:"journal_path,omitempty"`
	Phase         string `json:"phase,omitempty"`
	Error         string `json:"error,omitempty"`
}

type windowsManagedHooksLifecycleContext struct {
	opts          connector.WindowsCodexMachineRequirementsOptions
	manifestPath  string
	journalPath   string
	pendingPath   string
	targets       []windowsManagedHooksTeardownTarget
	claudeTargets []string
	fingerprint   string
}

func newWindowsManagedHooksLifecycleCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "managed-hooks-lifecycle-snapshot",
		Short:  "Transactionally snapshot managed machine-hook enrollment",
		Hidden: true,
	}
	for _, action := range []string{"capture", "restore", "retire"} {
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
	if action != "capture" && action != "restore" && action != "retire" {
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
	pendingExists, err := windowsManagedHooksLifecyclePendingExists(ctx.pendingPath)
	if err != nil {
		return fail(err)
	}
	if action != "retire" && !pendingExists {
		return fail(errors.New(
			"managed-hook lifecycle snapshot requires an authenticated pending lifecycle transaction",
		))
	}

	identity := windowsManagedHooksLifecycleJournal{
		SchemaVersion:       windowsManagedHooksLifecycleSchema,
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
		journal := identity
		journal.Phase = "captured"
		journal.PriorClaudeTargetSIDs = prior
		journal.Claude = snapshot
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
		if err := enterprisehooks.RestoreWindowsClaudeManagedPolicySnapshot(
			enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions{
				HookExecutable:     journal.HookBinary,
				GatewayAddr:        journal.GatewayAddr,
				GatewayServiceName: journal.GatewayServiceName,
				TargetSIDs:         append([]string(nil), journal.PriorClaudeTargetSIDs...),
			},
			windowsManagedHooksClaudeOptions(ctx.opts, ctx.claudeTargets),
			journal.Claude,
		); err != nil {
			return fail(err)
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
	stateRoot := filepath.Dir(filepath.Dir(opts.OwnershipPath))
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
	targets, claudeTargets, _, err := windowsManagedHooksTeardownTargets(manifest)
	if err != nil {
		return ctx, err
	}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(targets)
	if err != nil {
		return ctx, err
	}
	installState := filepath.Join(stateRoot, "install")
	ctx = windowsManagedHooksLifecycleContext{
		opts:          opts,
		manifestPath:  manifestPath,
		journalPath:   filepath.Join(installState, windowsManagedHooksLifecycleJournalFile),
		pendingPath:   filepath.Join(installState, "pending.json"),
		targets:       targets,
		claudeTargets: claudeTargets,
		fingerprint:   fingerprint,
	}
	return ctx, nil
}

func windowsManagedHooksLifecyclePendingExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("pending lifecycle transaction is not a regular non-link file")
	}
	if err := managed.ValidateTrustedFilePath(path, "pending Windows enterprise lifecycle transaction"); err != nil {
		return false, err
	}
	return true, nil
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

func validateWindowsManagedHooksLifecycleJournal(
	journal windowsManagedHooksLifecycleJournal,
	identity windowsManagedHooksLifecycleJournal,
) error {
	if journal.SchemaVersion != windowsManagedHooksLifecycleSchema ||
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
	return nil
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
