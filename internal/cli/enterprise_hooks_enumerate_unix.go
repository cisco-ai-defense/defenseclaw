//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// `enterprise hooks enumerate` is the standalone Unix enumerator: it
// discovers eligible local and directory users, discovers their agent
// versions in their own worker, and publishes the guardian manifest. The
// guardian's file watch picks the new manifest up.

const enterpriseHookEnumeratorStateFile = ".targets-enumerator-state.json"

type enterpriseHooksEnumerateOptions struct {
	manifest   string
	descriptor string
	interval   time.Duration
	jsonOut    bool
	dryRun     bool
}

var enterpriseHooksEnumerateOpts = enterpriseHooksEnumerateOptions{}

var enterpriseHooksEnumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "Publish the standalone guardian's per-user targets (Linux and macOS)",
	Long: `Discover the users this host should protect and publish the hook guardian
manifest. Candidates are local and directory (SSSD, LDAP, AD, systemd-userdb)
accounts, users with a login session, owners of homes under the allowed home
roots, and enterprise.enrollment.include_users. Each is filtered by uid range,
login shell, home trust and the include/exclude user and group lists, and its
agent versions are discovered with that user's own credentials.

A directory outage never revokes a known user; only repeated definitive
"no such user" answers do. Byte-identical manifests are not rewritten.

Standalone profile only. With enterprise.enrollment.mode=manifest the
administrator publishes the manifest and this command does nothing.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runEnterpriseHooksEnumerate(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), enterpriseHooksEnumerateOpts)
	},
}

func init() {
	flags := enterpriseHooksEnumerateCmd.Flags()
	flags.StringVar(&enterpriseHooksEnumerateOpts.manifest, "manifest", "", "absolute path of the guardian targets.yaml to maintain (default on a standalone host: its layout's manifest)")
	flags.StringVar(&enterpriseHooksEnumerateOpts.descriptor, "descriptor", "", "managed runtime descriptor (default: the standalone layout's)")
	flags.DurationVar(&enterpriseHooksEnumerateOpts.interval, "interval", 0, "run every interval as a service; 0 runs one cycle")
	flags.BoolVar(&enterpriseHooksEnumerateOpts.jsonOut, "json", false, "print each cycle's report as JSON")
	flags.BoolVar(&enterpriseHooksEnumerateOpts.dryRun, "dry-run", false, "print the manifest instead of publishing it")
	_ = flags.MarkHidden("descriptor")
	enterpriseHooksCmd.AddCommand(enterpriseHooksEnumerateCmd)

	revokeFlags := enterpriseHooksRevokeGoneCmd.Flags()
	revokeFlags.StringVar(&enterpriseHooksRevokeGoneOpts.manifest, "manifest", "", "absolute path of the guardian targets.yaml to maintain")
	revokeFlags.BoolVar(&enterpriseHooksRevokeGoneOpts.jsonOut, "json", false, "print the result as JSON")
	enterpriseHooksCmd.AddCommand(enterpriseHooksRevokeGoneCmd)
}

// `enterprise hooks revoke-gone` is the immediate form of the enumerator's
// revocation of deleted accounts. The enumerator removes a deleted
// account's targets after enterprisehooks.UnixRevokeAfterMisses cycles, and
// until then the guardian reports each as a failed target, so verify and
// reconcile fail for the whole host. `enterprise linux|macos repair` runs
// this while the guardian and the enumerator are stopped.

type enterpriseHooksRevokeGoneOptions struct {
	manifest string
	jsonOut  bool
}

var enterpriseHooksRevokeGoneOpts = enterpriseHooksRevokeGoneOptions{}

var enterpriseHooksRevokeGoneCmd = &cobra.Command{
	Use:          "revoke-gone",
	Short:        "Internal: remove the targets of accounts that no longer exist (run by repair)",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runEnterpriseHooksRevokeGone(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), enterpriseHooksRevokeGoneOpts)
	},
}

type enterpriseHooksRevokeGoneReport struct {
	enterprisehooks.UnixRevokeGoneReport
	Manifest string `json:"manifest"`
	Changed  bool   `json:"changed"`
	Idle     bool   `json:"idle,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// enterpriseHooksRevokeGoneRootCheck is replaceable in unprivileged tests.
var enterpriseHooksRevokeGoneRootCheck = func() error {
	if euid := os.Geteuid(); euid != 0 {
		return fmt.Errorf("enterprise hooks revoke-gone: run as root (euid=%d)", euid)
	}
	return nil
}

func runEnterpriseHooksRevokeGone(ctx context.Context, stdout, stderr io.Writer, opts enterpriseHooksRevokeGoneOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	manifestPath := filepath.Clean(strings.TrimSpace(opts.manifest))
	if strings.TrimSpace(opts.manifest) == "" || !filepath.IsAbs(manifestPath) {
		return errors.New("enterprise hooks revoke-gone: --manifest must be an absolute path")
	}
	if !enterpriseHooksStandaloneUnixActive() {
		return errors.New("enterprise hooks revoke-gone: available only in the standalone enterprise profile")
	}
	if err := enterpriseHooksRevokeGoneRootCheck(); err != nil {
		return err
	}
	current, err := enterpriseHooksEnumerateConfigLoader()
	if err != nil {
		return fmt.Errorf("enterprise hooks revoke-gone: load managed config: %w", err)
	}
	if !current.StandaloneEnterprise() {
		return errors.New("enterprise hooks revoke-gone: the managed config is not the standalone profile")
	}
	report := enterpriseHooksRevokeGoneReport{Manifest: manifestPath}
	if strings.EqualFold(strings.TrimSpace(current.Enterprise.Enrollment.Mode), config.EnterpriseEnrollmentManifest) {
		report.Idle = true
		report.Reason = "enterprise.enrollment.mode is manifest; the administrator publishes targets"
	} else {
		statePath := enterpriseHookEnumeratorStatePath(manifestPath)
		state := enterprisehooks.LoadUnixEnumeratorState(statePath)
		manifest, result, err := enterprisehooks.RevokeGoneUnixTargets(ctx, enterprisehooks.UnixRevokeGoneOptions{
			ExistingManifestPath: manifestPath,
			Resolver:             unixidentity.NewCachingResolver(enterpriseHooksEnumerateResolver(ctx)),
			LocalAccounts: func() (map[string]int, error) {
				return enterpriseHooksEnumerateLocalAccounts(ctx)
			},
			DirectoryConfigured: enterpriseHooksEnumerateDirectoryConfigured,
			State:               state,
			Logger: func(subject, reason string) {
				fmt.Fprintf(stderr, "[hook-enumerator] %s: %s\n", subject, reason)
			},
		})
		if err != nil {
			return err
		}
		report.UnixRevokeGoneReport = result
		if len(result.Revoked) > 0 {
			if report.Changed, err = enterpriseHooksEnumerateManifestWriter(manifestPath, manifest); err != nil {
				return err
			}
			if err := enterprisehooks.SaveUnixEnumeratorState(statePath, state); err != nil {
				fmt.Fprintf(stderr, "[hook-enumerator] warn: could not persist enumerator state: %v\n", err)
			}
		}
	}
	if opts.jsonOut {
		return json.NewEncoder(stdout).Encode(report)
	}
	switch {
	case report.Idle:
		fmt.Fprintf(stdout, "idle: %s\n", report.Reason)
	case len(report.Revoked) == 0:
		fmt.Fprintln(stdout, "no targets of deleted accounts")
	default:
		fmt.Fprintf(stdout, "removed the targets of accounts that no longer exist: %s\n", strings.Join(report.Revoked, ", "))
	}
	for _, kept := range report.Kept {
		fmt.Fprintf(stdout, "kept %s\n", kept)
	}
	return nil
}

type enterpriseHooksEnumerateReport struct {
	enterprisehooks.UnixEnumerationReport
	Manifest string `json:"manifest"`
	Changed  bool   `json:"changed"`
	Idle     bool   `json:"idle,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func runEnterpriseHooksEnumerate(ctx context.Context, stdout, stderr io.Writer, opts enterpriseHooksEnumerateOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	manifestPath := filepath.Clean(strings.TrimSpace(opts.manifest))
	if strings.TrimSpace(opts.manifest) == "" || !filepath.IsAbs(manifestPath) {
		return errors.New("enterprise hooks enumerate: --manifest must be an absolute path")
	}
	if opts.interval < 0 {
		return errors.New("enterprise hooks enumerate: --interval must not be negative")
	}
	if !enterpriseHooksStandaloneUnixActive() {
		return errors.New("enterprise hooks enumerate: available only in the standalone enterprise profile")
	}
	if !opts.dryRun {
		if err := enterpriseHookStandaloneMutationPreflight(); err != nil {
			return err
		}
	}
	state := enterprisehooks.LoadUnixEnumeratorState(enterpriseHookEnumeratorStatePath(manifestPath))
	for {
		report, err := runEnterpriseHooksEnumerateCycle(ctx, stderr, manifestPath, opts, state)
		if err != nil {
			if opts.interval == 0 {
				return err
			}
			fmt.Fprintf(stderr, "[hook-enumerator] cycle failed: %v\n", err)
		} else {
			printEnterpriseHooksEnumerateReport(stdout, stderr, report, opts.jsonOut)
		}
		if opts.interval == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.interval):
		}
	}
}

func enterpriseHookEnumeratorStatePath(manifestPath string) string {
	return filepath.Join(filepath.Dir(manifestPath), enterpriseHookEnumeratorStateFile)
}

// enterpriseHooksEnumerateConfigLoader is replaceable in tests.
var enterpriseHooksEnumerateConfigLoader = func() (*config.Config, error) {
	loaded, _, err := loadGatewayConfigV8(config.ConfigPath())
	return loaded, err
}

func runEnterpriseHooksEnumerateCycle(
	ctx context.Context,
	stderr io.Writer,
	manifestPath string,
	opts enterpriseHooksEnumerateOptions,
	state *enterprisehooks.UnixEnumeratorState,
) (enterpriseHooksEnumerateReport, error) {
	report := enterpriseHooksEnumerateReport{Manifest: manifestPath}
	// Reload each cycle so an administrator's enrollment change applies
	// without restarting the service.
	current, err := enterpriseHooksEnumerateConfigLoader()
	if err != nil {
		return report, fmt.Errorf("load managed config: %w", err)
	}
	if !current.StandaloneEnterprise() {
		return report, errors.New("the managed config is no longer the standalone profile")
	}
	if strings.EqualFold(strings.TrimSpace(current.Enterprise.Enrollment.Mode), config.EnterpriseEnrollmentManifest) {
		report.Idle = true
		report.Reason = "enterprise.enrollment.mode is manifest; the administrator publishes targets"
		return report, nil
	}
	machinePolicy, err := enterpriseHooksEnumerateMachinePolicyConnectors(opts.descriptor)
	if err != nil {
		return report, err
	}
	resolver := unixidentity.NewCachingResolver(enterpriseHooksEnumerateResolver(ctx))
	uidMin, uidMax := unixidentity.DefaultUIDRange()
	homeRoots := append(enterprisehooks.DefaultUnixHomeRoots(runtime.GOOS), current.Enterprise.Enrollment.HomeRoots...)
	manifest, cycle, err := enterprisehooks.EnumerateUnix(ctx, current, newEnterpriseHooksConnectorRegistry(), enterprisehooks.UnixEnumerateOptions{
		ExistingManifestPath: manifestPath,
		Resolver:             resolver,
		HomeRoots:            homeRoots,
		UIDMin:               uidMin,
		UIDMax:               uidMax,
		LocalAccounts: func() (map[string]int, error) {
			return enterpriseHooksEnumerateLocalAccounts(ctx)
		},
		DirectoryConfigured:     enterpriseHooksEnumerateDirectoryConfigured,
		MachinePolicyConnectors: machinePolicy,
		OwnershipOffConnectors:  enterprisepolicy.OwnershipOffConnectors(current, runtime.GOOS),
		SessionUIDs:             enterpriseHookSessionUIDs,
		Discover:                enterpriseHooksEnumerateDiscover,
		DiscoverStatic:          enterpriseHooksEnumerateDiscoverStatic,
		MachineVersion:          enterprisehooks.DiscoverUnixMachineAgentVersion,
		State:                   state,
		Logger: func(subject, reason string) {
			fmt.Fprintf(stderr, "[hook-enumerator] %s: %s\n", subject, reason)
		},
	})
	if err != nil {
		return report, err
	}
	report.UnixEnumerationReport = cycle
	if opts.dryRun {
		data, err := enterprisehooks.MarshalUnixTargetsManifest(manifest)
		if err != nil {
			return report, err
		}
		fmt.Fprintf(stderr, "%s", data)
		return report, nil
	}
	report.Changed, err = enterpriseHooksEnumerateManifestWriter(manifestPath, manifest)
	if err != nil {
		return report, err
	}
	if err := enterprisehooks.SaveUnixEnumeratorState(enterpriseHookEnumeratorStatePath(manifestPath), state); err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] warn: could not persist enumerator state: %v\n", err)
	}
	// The guardian runs the per-user foreign-hook cleanup for every eligible
	// account, including users whose connectors are all machine policy and
	// who therefore have no manifest rows.
	if err := enterpriseHooksEnumerateEligibleWriter(enterprisehooks.UnixEligibleAccountsPath(manifestPath), cycle.EligibleAccounts); err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] warn: could not publish the eligible accounts: %v\n", err)
	}
	// Status and verify report agents found installed but not enrollable,
	// so an unprotected agent is never a silent gap.
	if err := enterpriseHooksEnumerateUnprotectedWriter(enterprisehooks.UnprotectedAgentsPath(manifestPath), cycle.Unprotected); err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] warn: could not publish the unprotected agents: %v\n", err)
	}
	return report, nil
}

// The cycle's root-only publications; tests replace them, since only root
// can satisfy their root-owned directory chain.
var (
	enterpriseHooksEnumerateManifestWriter    = enterprisehooks.WriteUnixTargetsManifestAtomic
	enterpriseHooksEnumerateEligibleWriter    = enterprisehooks.WriteUnixEligibleAccounts
	enterpriseHooksEnumerateUnprotectedWriter = enterprisehooks.WriteUnixUnprotectedAgents
)

// enterpriseHooksEnumerateResolver is replaceable in tests.
var enterpriseHooksEnumerateResolver = func(ctx context.Context) unixidentity.Resolver {
	return unixidentity.Default(ctx)
}

// The local account database and the directory configuration tell a
// deleted local account from a directory account during an outage; both
// are replaceable in tests.
var (
	enterpriseHooksEnumerateLocalAccounts       = unixidentity.LocalAccounts
	enterpriseHooksEnumerateDirectoryConfigured = unixidentity.DirectoryConfigured
)

func enterpriseHooksEnumerateMachinePolicyConnectors(descriptorPath string) ([]string, error) {
	descriptorPath = strings.TrimSpace(descriptorPath)
	if descriptorPath == "" {
		layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
		if err != nil {
			return nil, err
		}
		descriptorPath = layout.DescriptorPath
	}
	descriptor, err := managed.LoadRuntimeDescriptor(descriptorPath)
	if errors.Is(err, managed.ErrNoRuntimeDescriptor) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load managed runtime descriptor: %w", err)
	}
	return append([]string{}, descriptor.MachinePolicyConnectors...), nil
}

// enterpriseHooksEnumerateDiscover asks the target user's worker for the
// installed agent versions. The worker's answer is user-influenced, so
// every version is re-validated here.
func enterpriseHooksEnumerateDiscover(ctx context.Context, account unixidentity.Account, connectors []string) (map[string]string, map[string]string, error) {
	return enterpriseHooksEnumerateDiscoverWith(ctx, account, connectors, false)
}

// enterpriseHooksEnumerateDiscoverStatic is enterpriseHooksEnumerateDiscover
// for an untrusted home: the worker executes nothing there.
func enterpriseHooksEnumerateDiscoverStatic(ctx context.Context, account unixidentity.Account, connectors []string) (map[string]string, map[string]string, error) {
	return enterpriseHooksEnumerateDiscoverWith(ctx, account, connectors, true)
}

func enterpriseHooksEnumerateDiscoverWith(ctx context.Context, account unixidentity.Account, connectors []string, static bool) (map[string]string, map[string]string, error) {
	response, err := enterpriseHookWorkerRunner(ctx, enterpriseHookWorkerAccount{
		UID:  account.UID,
		GID:  account.GID,
		User: account.Name,
		Home: filepath.Clean(account.Home),
	}, enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpDiscover, Standalone: true, Connectors: connectors, StaticDiscovery: static})
	if err != nil {
		return nil, nil, err
	}
	wanted := map[string]bool{}
	for _, name := range connectors {
		wanted[strings.ToLower(strings.TrimSpace(name))] = true
	}
	versions := map[string]string{}
	for name, version := range response.Versions {
		if wanted[name] && enterprisehooks.ValidUnixAgentVersion(version) {
			versions[name] = version
		}
	}
	reasons := map[string]string{}
	for name, reason := range response.Reasons {
		if wanted[name] {
			if len(reason) > 256 {
				reason = reason[:256]
			}
			reasons[name] = reason
		}
	}
	return versions, reasons, nil
}

// enterpriseHookSessionUIDs lists uids with a live login session:
// systemd-logind's per-user records on Linux, the console owner on macOS.
var enterpriseHookSessionUIDs = func() []int {
	if runtime.GOOS == "darwin" {
		info, err := os.Stat("/dev/console")
		if err != nil {
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			return []int{int(st.Uid)}
		}
		return nil
	}
	return enterpriseHookSessionUIDsFrom("/run/systemd/users")
}

func enterpriseHookSessionUIDsFrom(dir string) []int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var uids []int
	for _, entry := range entries {
		uid, err := strconv.Atoi(entry.Name())
		if err == nil && uid > 0 && strconv.Itoa(uid) == entry.Name() {
			uids = append(uids, uid)
		}
	}
	sort.Ints(uids)
	return uids
}

func printEnterpriseHooksEnumerateReport(stdout, stderr io.Writer, report enterpriseHooksEnumerateReport, jsonOut bool) {
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(report)
		return
	}
	if report.Idle {
		fmt.Fprintf(stderr, "[hook-enumerator] idle: %s\n", report.Reason)
		return
	}
	fmt.Fprintf(stderr, "[hook-enumerator] %d candidates, %d eligible, %d rows (%d new, %d deferred, %d revoked), manifest changed=%t\n",
		report.Candidates, report.Eligible, report.Rows, report.New, report.Deferred, report.Revoked, report.Changed)
}
