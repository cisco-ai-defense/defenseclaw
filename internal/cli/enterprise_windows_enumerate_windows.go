// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
	"github.com/defenseclaw/defenseclaw/internal/winsession"
)

// enterpriseWindowsEnumerateDefaultInterval is the SCM-service
// default sleep between cycles. Matches macOS's
// `com.cisco.secureclient.defenseclaw.hook-enumerator` LaunchDaemon
// `StartInterval = 300` (5 minutes).
const enterpriseWindowsEnumerateDefaultInterval = 5 * time.Minute

// enterpriseWindowsEnumerateInitialCycleDelay bounds the first audit
// wait so a `--deferred-config` service start doesn't have to wait a
// full 5-minute interval before profile drift is reported.
// Set to 30 s so the gateway + guardian services publish their
// "starting" health lines FIRST (each takes ~5-10 s on a cold-boot);
// the enumerator's first cycle then runs, and any hooked-in health
// dashboard sees a coherent startup ordering.
//
// Tuneable in a follow-up if telemetry shows this
// is too long / too short.
const enterpriseWindowsEnumerateInitialCycleDelay = 30 * time.Second

// enterpriseWindowsEnumerateCycleTimeout bounds a single enumeration
// cycle so a wedged registry walk / IO can't starve subsequent
// ticks.
const enterpriseWindowsEnumerateCycleTimeout = 60 * time.Second

// enterpriseWindowsEnumerateSessionSettle delays the extra cycle a sign-in
// triggers (standalone profile only) so Windows finishes creating a first
// profile, and a burst of session events runs one cycle.
var enterpriseWindowsEnumerateSessionSettle = 15 * time.Second

// enterpriseWindowsEnumerateSessionSettleAfter arms the settle window. Tests
// replace it to fire the window on an explicit event instead of a clock.
var enterpriseWindowsEnumerateSessionSettleAfter = time.After

// enterpriseWindowsEnumeratePrivateWalkLate fires when a profile walk the last
// cycle could not wait for has finished. Tests replace it.
var enterpriseWindowsEnumeratePrivateWalkLate = enterprisehooks.WindowsPrivateWalkCompletedLate

// enterpriseWindowsEnumerateSessionNow reads the clock for sign-in times.
// Tests replace it so a late sign-in's remaining settle time is exact.
var enterpriseWindowsEnumerateSessionNow = time.Now

// enterpriseWindowsEnumerateOptions carries the CLI flags for the
// `enterprise windows enumerate` subcommand. Parsed in
// `newEnterpriseWindowsEnumerateCommand`.
type enterpriseWindowsEnumerateOptions struct {
	manifestPath string
	interval     time.Duration
	once         bool
	initialDelay time.Duration
}

// newEnterpriseWindowsEnumerateCommand wires the `enterprise windows
// enumerate` cobra subcommand under the existing
// `enterpriseWindowsCmd` group.
//
// Two modes:
//
//   - `--once`: runs a single enumeration cycle synchronously and
//     exits. Used by the installer's fresh-install path (replaces
//     the retired inline PowerShell walk at
//     `DefenseClawEnterprise.psm1:3663-3736`).
//   - default (no `--once`): enters the interval-loop the SCM
//     service invokes at boot. On every tick it publishes an
//     updated targets.yaml, auto-authorizing newly-discovered
//     (SID, Connector) rows whose per-user profile contains a
//     supported CLI (parity with macOS render-targets.sh). Rows
//     with no discoverable CLI are silently skipped. The
//     byte-identical short-circuit in WriteTargetsManifestAtomic
//     keeps steady-state ticks free of file mutation.
//
// Each tick auto-authorizes rather than only auditing (macOS parity);
// see docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md residual-risk section.
func newEnterpriseWindowsEnumerateCommand() *cobra.Command {
	opts := &enterpriseWindowsEnumerateOptions{
		interval:     enterpriseWindowsEnumerateDefaultInterval,
		initialDelay: enterpriseWindowsEnumerateInitialCycleDelay,
	}
	cmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Publish Windows managed-enterprise hook enrollment on every tick",
		Long: `Walk HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList to
discover local user profiles, filter to local/domain (S-1-5-21-…) and Microsoft
Entra ID (S-1-12-1-…) interactive users, and
publish an updated hook-guardian targets.yaml.

Two modes:

  * default: enter an interval loop suitable for an SCM ImagePath. On every
    tick the service publishes an updated targets.yaml, auto-authorizing
    newly-discovered (SID, Connector) rows whose per-user profile contains
    a supported CLI. Profiles with no discoverable CLI are omitted from the
    manifest without failing the cycle — the per-row reason is emitted to
    stderr under the '[hook-enumerator] skipped ...' line so an operator
    can see why a specific user was left out (macOS parity). The
    byte-identical short-circuit in WriteTargetsManifestAtomic keeps
    steady-state ticks free of file mutation.

  * --once: run a single cycle synchronously and exit. Used by the
    installer to publish targets.yaml before deployment commit.

Both modes authenticate the manifest's ancestry, exact AdminFile descriptor,
regular-file identity, link contract, and schema, and both stage an authorized
update under the exact AdminFile contract before atomic replace. On trust
drift, both modes fail closed and leave the committed manifest untouched.

Managed-enterprise Windows only. macOS's LaunchDaemon-based
'hook-enumerator' + render-targets.sh covers the darwin side;
nothing about this subcommand is invoked on non-Windows OSes.
`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withExitCode(
				runEnterpriseWindowsEnumerate(cmd.Context(), cmd, opts),
				windowsEnterpriseFailureExitCode,
			)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.manifestPath, "manifest", "", "absolute path to the hook-guardian targets.yaml this enumerator maintains (required)")
	flags.DurationVar(&opts.interval, "interval", enterpriseWindowsEnumerateDefaultInterval, "sleep between enumeration cycles when running as a service")
	flags.BoolVar(&opts.once, "once", false, "run a single cycle synchronously and exit; --interval is then unused")
	flags.DurationVar(&opts.initialDelay, "initial-cycle-delay", enterpriseWindowsEnumerateInitialCycleDelay, "wait this long before the first interval-loop cycle so the gateway + guardian can publish their startup health lines first")
	return cmd
}

// runEnterpriseWindowsEnumerate is the RunE for the subcommand.
// Split out so unit tests can drive it with a fake context + fake
// clock; the cobra command is a thin wrapper.
func runEnterpriseWindowsEnumerate(
	ctx context.Context,
	cmd *cobra.Command,
	opts *enterpriseWindowsEnumerateOptions,
) error {
	if opts == nil {
		return errors.New("enterprise windows enumerate: nil options")
	}
	manifestPath := strings.TrimSpace(opts.manifestPath)
	if manifestPath == "" {
		return errors.New("enterprise windows enumerate: --manifest is required")
	}
	if !filepath.IsAbs(manifestPath) {
		return fmt.Errorf("enterprise windows enumerate: --manifest must be absolute (got %q)", manifestPath)
	}
	if opts.interval <= 0 && !opts.once {
		return errors.New("enterprise windows enumerate: --interval must be positive unless --once is set")
	}

	stderr := cmd.ErrOrStderr()
	fmt.Fprintf(stderr, "[hook-enumerator] windows: manifest=%s interval=%s once=%t initial_delay=%s\n",
		manifestPath, opts.interval, opts.once, opts.initialDelay)

	if opts.once {
		return runEnterpriseWindowsEnumerateSingleCycle(ctx, stderr, manifestPath)
	}

	return runEnterpriseWindowsEnumerateInterval(ctx, stderr, opts, manifestPath)
}

// runEnterpriseWindowsEnumerateSingleCycle runs one bounded cycle,
// publishes targets.yaml and returns. Both call sites publish:
//
//   - The `--once` installer path publishes the initial pre-commit
//     targets.yaml.
//   - The long-running SCM interval loop publishes an updated
//     targets.yaml on every tick (auto-authorize parity with
//     macOS render-targets.sh). Byte-identical short-circuit in
//     WriteTargetsManifestAtomic keeps steady-state ticks
//     mutation-free.
func runEnterpriseWindowsEnumerateSingleCycle(
	ctx context.Context,
	stderr io.Writer,
	manifestPath string,
) error {
	cycleCtx, cancel := context.WithTimeout(ctx, enterpriseWindowsEnumerateCycleTimeout)
	defer cancel()

	cfg, cfgErr := enterpriseWindowsEnumerateConfigLoader()
	if cfgErr != nil {
		// A missing config in managed_enterprise mode is a "waiting
		// for configuration" state — logged, not fatal. Interval-loop
		// callers retry next tick; --once callers exit non-zero so an
		// installer can distinguish "no config yet" from "cycle wrote
		// a manifest".
		if isEnterpriseWindowsEnumerateConfigMissing(cfgErr) {
			fmt.Fprintf(stderr, "[hook-enumerator] config.yaml unavailable; skipping cycle (waiting_for_config): %v\n", cfgErr)
			return cfgErr
		}
		return fmt.Errorf("enterprise windows enumerate: load config: %w", cfgErr)
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return fmt.Errorf("enterprise windows enumerate: deployment_mode=%q is not managed_enterprise; refusing to run", cfg.DeploymentMode)
	}

	start := time.Now()
	if reason := standaloneWindowsEnumerateIdleReason(cfg); reason != "" {
		fmt.Fprintf(stderr, "[hook-enumerator] cycle idle: %s\n", reason)
		// The administrator's targets still need gateway inventory access
		// and group identity facts, but the enumerator never rewrites them.
		if authored, loadErr := enterprisehooks.LoadManifest(manifestPath); loadErr == nil {
			if cfg.StandaloneEnterprise() {
				publishEnterpriseWindowsManifestIdentity(cycleCtx, stderr, cfg, manifestPath, authored)
			}
			if grantErr := enterprisehooks.GrantGatewayInventoryReadForManifest(authored, "", !cfg.SecureClientIntegration(), enumerationLoggerForStderr(stderr)); grantErr != nil {
				fmt.Fprintf(stderr, "[hook-enumerator] inventory-DACL pass failed: %v\n", grantErr)
			}
			_ = publishEnterpriseWindowsMCPServers(cfg, authored, stderr) // logged; the next cycle publishes again
			publishEnterpriseWindowsIDEAppData(cfg, authored, stderr)
		} else if cfg.StandaloneEnterprise() {
			fmt.Fprintf(stderr, "[hook-enumerator] WARN could not load administrator targets for identity facts: %v\n", loadErr)
		}
		// Manifest mode gives target authorship to the administrator, not
		// install inspection. Keep checking every eligible profile so a
		// private runnable copy can still lower managed health.
		return publishEnterpriseWindowsManifestInstallScan(cycleCtx, stderr, cfg, manifestPath)
	}
	logf := enumerationLoggerForStderr(stderr)
	enumerateOpts := standaloneWindowsEnumerateOptions(cfg, enterprisehooks.EnumerateOptions{
		ExistingManifestPath: manifestPath,
		Logger:               logf,
	})
	standalone := cfg.StandaloneEnterprise()
	var unprotected []enterprisehooks.UnprotectedAgent
	var excluded []enterprisehooks.ManifestTarget
	var ownerUnknown []enterprisehooks.UnprotectedAgent
	// The profiles the last cycle enrolled, so the gateway's read access
	// can be taken from those this cycle drops.
	previous, previousErr := enterprisehooks.Manifest{}, errors.New("not loaded")
	if standalone {
		previous, previousErr = enterprisehooks.LoadManifest(manifestPath)
	}
	if standalone {
		cache, cacheErr := enterpriseWindowsEnumerateGroupCacheLoader(enterprisehooks.WindowsEnrollmentGroupsCachePath(manifestPath))
		if cacheErr != nil {
			fmt.Fprintf(stderr, "[hook-enumerator] WARN enrollment group cache is unreadable; starting from signed-in sessions only: %v\n", cacheErr)
			cache = enterprisehooks.NewWindowsEnrollmentGroupCache()
		}
		enumerateOpts.GroupCache = cache
		enterprisehooks.SetUnverifiedVersionsPolicy(cfg.Enterprise.Enrollment.UnverifiedVersionsFor)
		enumerateOpts.ReportUnprotected = func(agent enterprisehooks.UnprotectedAgent) {
			unprotected = append(unprotected, agent)
		}
		enumerateOpts.ReportExcluded = func(target enterprisehooks.ManifestTarget) {
			excluded = append(excluded, target)
		}
		// A running agent no row enrolls is recorded too (GAP-0226), and so is
		// one whose account resolves to no SID.
		enumerateOpts.RunningAgents, ownerUnknown = enterpriseWindowsEnumerateRunningAgents(stderr, enterprisehooks.EffectiveWindowsHookConnectors(cfg))
	}
	manifest, err := enterpriseWindowsEnumerateProfileEnumerator(cycleCtx, cfg, enumerateOpts)
	if err != nil {
		return fmt.Errorf("enterprise windows enumerate: walk profiles: %w", err)
	}

	changed, err := enterpriseWindowsEnumerateManifestWriter(manifestPath, manifest)
	if err != nil {
		return fmt.Errorf("enterprise windows enumerate: write manifest: %w", err)
	}
	if standalone {
		// The cache keeps signed-out users' last seen group membership;
		// the record lets status and verify name every agent found
		// installed but not enrollable, so none is a silent gap.
		if _, cacheErr := enterpriseWindowsEnumerateGroupCacheWriter(enterprisehooks.WindowsEnrollmentGroupsCachePath(manifestPath), enumerateOpts.GroupCache); cacheErr != nil {
			fmt.Fprintf(stderr, "[hook-enumerator] WARN could not save the enrollment group cache: %v\n", cacheErr)
		}
		// The gateway's service account cannot read that cache: publish each
		// user's verified directory facts and named groups where it can.
		identityDir := enterprisehooks.IdentitySpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
		// An excluded account's groups are not published as trusted
		// identity facts (GAP-1264), and the pass ends with the cycle
		// (GAP-1049).
		excludedSIDs := make([]string, 0, len(excluded))
		for _, target := range excluded {
			excludedSIDs = append(excludedSIDs, target.SID)
		}
		if spoolErr := enterpriseWindowsIdentitySpoolWriter(cycleCtx, identityDir, enumerateOpts.GroupCache, excludedSIDs, enterpriseWindowsConnectorEmails(stderr, cfg, manifest), enterpriseHookAuthorizationOwnershipSetter, func(format string, args ...any) {
			fmt.Fprintf(stderr, format+"\n", args...)
		}); spoolErr != nil {
			fmt.Fprintf(stderr, "[hook-enumerator] WARN could not publish identity facts: %v\n", spoolErr)
		}
		_ = publishEnterpriseWindowsMCPServers(cfg, manifest, stderr) // logged; the next cycle publishes again
		publishEnterpriseWindowsIDEAppData(cfg, manifest, stderr)
		unprotected = append(unprotected, ownerUnknown...)
		if _, recordErr := enterpriseWindowsEnumerateUnprotectedWriter(manifestPath, unprotected); recordErr != nil {
			fmt.Fprintf(stderr, "[hook-enumerator] WARN could not publish the unprotected agents: %v\n", recordErr)
		}
		for _, agent := range unprotected {
			fmt.Fprintf(stderr, "[hook-enumerator] WARN %s: %s\n", agent.Code, agent.Message())
		}
	}
	if standalone {
		// A deleted local account's ACP enrollments go with it, as its hook
		// rows do (GAP-0367).
		revokeEnterpriseACPEnrollmentsOfDeletedSIDs(cfg.DataDir, windowsEnterpriseAccountDeleted, stderr)
		// The copies a revoke could not remove while their user was signed
		// out go at the next cycle the user is signed in for; a sign-in
		// starts one (GAP-0718).
		cleanEnterpriseACPUserCopies(cfg.DataDir, removeEnterpriseACPUserCopyAsUser, windowsEnterpriseAccountDeleted, stderr)
	}
	// Sibling pass: ensure the CertGateway service SID has Read+Execute on
	// each enrolled user's inventory dotdirs (~/.claude, ~/.codex, …). The
	// gateway runs under a virtual service account whose access to user
	// profiles is not implicit; without this grant the AI discovery scanner
	// walks the right paths but ReadDir returns access-denied and every
	// skill/plugin/rule/mcp signal is suppressed. Idempotent; per-directory
	// failures log-only so one bad DACL doesn't block the enumerator cycle.
	// The IDE plugin inventory's folders are added outside the Secure Client
	// profile, whose gateway has no IDE inventory.
	if grantErr := enterprisehooks.GrantGatewayInventoryReadForManifest(manifest, "", !cfg.SecureClientIntegration(), logf); grantErr != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] inventory-DACL pass failed: %v\n", grantErr)
	}
	if standalone {
		// A profile this cycle no longer grants (its account was added to
		// exclude_users, no enrolled agent is left, or its rows are all
		// disabled) loses the gateway's read access now, so its inventory
		// rows go at the next scan (GAP-0717, GAP-1193). A revoke that
		// fails stays in the grant ledger beside the manifest and is
		// retried, also after a restart (GAP-1269).
		var last *enterprisehooks.Manifest
		if previousErr == nil {
			last = &previous
		}
		reconcileEnterpriseWindowsInventoryGrants(stderr, manifestPath, last, manifest)
	}
	if standalone {
		revokeEnterpriseWindowsExcludedInventoryRead(stderr, excluded)
	}
	elapsed := time.Since(start)

	fmt.Fprintf(stderr, "[hook-enumerator] cycle complete users=%d targets=%d changed=%t elapsed=%s\n",
		countDistinctSIDs(manifest.Targets), len(manifest.Targets), changed, elapsed)
	if elapsed > 10*time.Second {
		// A cycle has a soft 10 s target on a 100-user
		// fleet; log a WARN if a single cycle overshoots so operators
		// see the degradation before the hard 60 s ceiling fires.
		fmt.Fprintf(stderr, "[hook-enumerator] WARN cycle exceeded 10 s target: %s\n", elapsed)
	}
	return nil
}

func publishEnterpriseWindowsManifestInstallScan(ctx context.Context, stderr io.Writer, cfg *config.Config, manifestPath string) error {
	cache, err := enterpriseWindowsEnumerateGroupCacheLoader(enterprisehooks.WindowsEnrollmentGroupsCachePath(manifestPath))
	if err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN enrollment group cache is unreadable; starting from signed-in sessions only: %v\n", err)
		cache = enterprisehooks.NewWindowsEnrollmentGroupCache()
	}
	sink := &enterpriseWindowsManifestScanSink{logf: enumerationLoggerForStderr(stderr)}
	opts := standaloneWindowsEnumerateOptions(cfg, enterprisehooks.EnumerateOptions{
		ExistingManifestPath: manifestPath,
		GroupCache:           cache,
		Logger:               sink.log,
		ReportUnprotected:    sink.report,
	})
	// The administrator's enabled targets are the enrollment: only they are
	// inspected, whatever the automatic filters say (GAP-0906). An
	// unreadable manifest leaves every eligible profile inspected.
	if authored, loadErr := enterprisehooks.LoadManifest(manifestPath); loadErr == nil {
		opts.ManifestSubjects = enterprisehooks.WindowsManifestSubjects(authored)
	} else {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN the administrator's targets are unreadable; inspecting every eligible profile: %v\n", loadErr)
	}
	enterprisehooks.SetUnverifiedVersionsPolicy(cfg.Enterprise.Enrollment.UnverifiedVersionsFor)
	var ownerUnknown []enterprisehooks.UnprotectedAgent
	opts.RunningAgents, ownerUnknown = enterpriseWindowsEnumerateRunningAgents(stderr, enterprisehooks.EffectiveWindowsHookConnectors(cfg))
	// The scan never decides targets in manifest mode, so a scan that did not
	// finish (the cycle ran out of time, ProfileList was unreadable, a call
	// stalled) never fails or holds the cycle or the install: the accounts it
	// did not inspect are published incomplete, and the next cycle scans
	// again.
	err = runEnterpriseWindowsManifestScanBounded(ctx, func() error {
		_, scanErr := enterpriseWindowsEnumerateProfileEnumerator(ctx, cfg, opts)
		return scanErr
	})
	agents := sink.close()
	if err != nil {
		if opts.ManifestSubjects == nil {
			fmt.Fprintf(stderr, "[hook-enumerator] WARN the manifest-mode install scan did not finish and the administrator's targets are unreadable; the coverage record is left as it was: %s\n", enumeratorErrorText(err))
			return nil
		}
		fmt.Fprintf(stderr, "[hook-enumerator] WARN the manifest-mode install scan did not finish; the enrolled accounts it did not inspect are reported incomplete: %s\n", enumeratorErrorText(err))
		agents = enterprisehooks.WindowsManifestScanIncomplete(opts.ManifestSubjects, opts.ExcludeUsers, agents, err)
	}
	agents = append(agents, ownerUnknown...)
	if _, err := enterpriseWindowsEnumerateUnprotectedWriter(manifestPath, agents); err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN could not publish the unprotected agents: %s\n", enumeratorErrorText(err))
	}
	for _, agent := range agents {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN %s: %s\n", agent.Code, agent.Message())
	}
	return nil
}

// enterpriseWindowsManifestScanGrace is how long past the cycle deadline the
// manifest-mode install scan may run before the cycle publishes without it.
var enterpriseWindowsManifestScanGrace = 2 * time.Second

// enterpriseWindowsManifestScanInFlight is set while a manifest-mode install
// scan has not returned. A call that stalls (an offline redirected home, a
// registry or account lookup that does not answer) never observes the
// context, so a later cycle answers timed out at once instead of starting a
// second scan behind the stalled one.
var enterpriseWindowsManifestScanInFlight atomic.Bool

// runEnterpriseWindowsManifestScanBounded runs scan in a worker and answers
// by ctx's deadline plus enterpriseWindowsManifestScanGrace. When the worker
// has not answered by then, its result is abandoned and the answer is a
// deadline error, so the caller publishes the uninspected accounts as scan
// timed out.
func runEnterpriseWindowsManifestScanBounded(ctx context.Context, scan func() error) error {
	if !enterpriseWindowsManifestScanInFlight.CompareAndSwap(false, true) {
		return fmt.Errorf("an earlier install scan has not returned: %w", context.DeadlineExceeded)
	}
	done := make(chan error, 1)
	go func() {
		err := scan()
		enterpriseWindowsManifestScanInFlight.Store(false)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	grace := time.NewTimer(enterpriseWindowsManifestScanGrace)
	defer grace.Stop()
	select {
	case err := <-done:
		return err
	case <-grace.C:
		return fmt.Errorf("the install scan did not answer by the cycle deadline: %w", context.DeadlineExceeded)
	}
}

// enterpriseWindowsManifestScanSink collects what the manifest-mode install
// scan reports and logs until close; an abandoned scan's later reports and
// log lines are dropped.
type enterpriseWindowsManifestScanSink struct {
	mu     sync.Mutex
	closed bool
	agents []enterprisehooks.UnprotectedAgent
	logf   enterprisehooks.EnumerationLogger
}

func (s *enterpriseWindowsManifestScanSink) report(agent enterprisehooks.UnprotectedAgent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.agents = append(s.agents, agent)
	}
}

func (s *enterpriseWindowsManifestScanSink) log(subject, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.logf(subject, reason)
	}
}

func (s *enterpriseWindowsManifestScanSink) close() []enterprisehooks.UnprotectedAgent {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return append([]enterprisehooks.UnprotectedAgent(nil), s.agents...)
}

// reconcileEnterpriseWindowsInventoryGrants revokes the gateway's inventory
// read access on the profiles the grant ledger holds that current gives no
// grant to, and records current's grants (enterprisehooks.
// ReconcileInventoryGrants).
func reconcileEnterpriseWindowsInventoryGrants(stderr io.Writer, manifestPath string, previous *enterprisehooks.Manifest, current enterprisehooks.Manifest) {
	result := enterprisehooks.ReconcileInventoryGrants(enterprisehooks.InventoryGrantLedger{
		Load: func() ([]enterprisehooks.ManifestTarget, error) {
			return enterpriseWindowsInventoryGrantLedgerLoader(manifestPath)
		},
		Save: func(targets []enterprisehooks.ManifestTarget) error {
			return enterpriseWindowsInventoryGrantLedgerSaver(manifestPath, targets)
		},
	}, previous, current, enterpriseWindowsInventoryReadRevoker)
	if result.LoadErr != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN the inventory grant ledger is unreadable; revoking from the last manifest: %s\n", enumeratorErrorText(result.LoadErr))
	}
	if result.RevokeErr != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN the gateway keeps read access on %d profile(s) no longer enrolled; the revoke failed and is retried at the next cycle: %s\n",
			countDistinctSIDs(result.Pending), enumeratorErrorText(result.RevokeErr))
	}
	if len(result.Revoked) > 0 {
		fmt.Fprintf(stderr, "[hook-enumerator] inventory-DACL revoked on %d profile(s) no longer enrolled\n", countDistinctSIDs(result.Revoked))
	}
	if result.SaveErr != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN could not save the inventory grant ledger: %s\n", enumeratorErrorText(result.SaveErr))
	}
}

// enumeratorErrorText is err's message, at most 512 bytes of it.
func enumeratorErrorText(err error) string {
	message := err.Error()
	if len(message) > 512 {
		message = message[:512] + "..."
	}
	return message
}

// enterpriseWindowsExcludedRevoked holds the excluded profiles whose
// inventory read access this enumerator process already took away.
var enterpriseWindowsExcludedRevoked = struct {
	sync.Mutex
	sids map[string]bool
}{sids: map[string]bool{}}

// revokeEnterpriseWindowsExcludedInventoryRead takes the gateway's inventory
// read access off every profile the enrollment excludes, once per profile
// while it stays excluded. A profile excluded before this install was
// granted by an earlier one (a cloned image) and was never in a manifest, so
// the dropped-profile revoke never reached it (GAP-1024).
func revokeEnterpriseWindowsExcludedInventoryRead(stderr io.Writer, excluded []enterprisehooks.ManifestTarget) {
	state := &enterpriseWindowsExcludedRevoked
	state.Lock()
	defer state.Unlock()
	current := map[string]bool{}
	var pending enterprisehooks.Manifest
	for _, target := range excluded {
		sid := strings.ToUpper(strings.TrimSpace(target.SID))
		if sid == "" || current[sid] {
			continue
		}
		current[sid] = true
		if !state.sids[sid] {
			pending.Targets = append(pending.Targets, target)
		}
	}
	for sid := range state.sids {
		if !current[sid] {
			delete(state.sids, sid)
		}
	}
	if len(pending.Targets) == 0 {
		return
	}
	if err := enterpriseWindowsInventoryReadRevoker(pending); err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN the gateway may keep read access on %d excluded profile(s); the revoke failed: %s\n",
			len(pending.Targets), enumeratorErrorText(err))
		return
	}
	for _, target := range pending.Targets {
		state.sids[strings.ToUpper(strings.TrimSpace(target.SID))] = true
	}
	fmt.Fprintf(stderr, "[hook-enumerator] inventory-DACL revoked on %d excluded profile(s)\n", len(pending.Targets))
}

// publishEnterpriseWindowsManifestIdentity refreshes signed-in token groups
// for administrator selected targets while keeping their manifest untouched.
func publishEnterpriseWindowsManifestIdentity(ctx context.Context, stderr io.Writer, cfg *config.Config, manifestPath string, manifest enterprisehooks.Manifest) {
	cachePath := enterprisehooks.WindowsEnrollmentGroupsCachePath(manifestPath)
	cache, err := enterpriseWindowsEnumerateGroupCacheLoader(cachePath)
	if err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN enrollment group cache is unreadable: %v\n", err)
		cache = enterprisehooks.NewWindowsEnrollmentGroupCache()
	}
	refreshed, err := enterpriseWindowsManifestGroupCacheRefresher(manifest, cache)
	if err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN active session groups are unreadable: %v\n", err)
	}
	if refreshed == nil {
		return
	}
	if _, err := enterpriseWindowsEnumerateGroupCacheWriter(cachePath, refreshed); err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN could not save the enrollment group cache: %v\n", err)
	}
	identityDir := enterprisehooks.IdentitySpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	if err := enterpriseWindowsIdentitySpoolWriter(ctx, identityDir, refreshed, nil, enterpriseWindowsConnectorEmails(stderr, cfg, manifest), enterpriseHookAuthorizationOwnershipSetter, func(format string, args ...any) {
		fmt.Fprintf(stderr, format+"\n", args...)
	}); err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN could not publish identity facts: %v\n", err)
	}
}

// enterpriseWindowsConnectorEmails reads the enrolled profiles' Claude Code
// and Codex addresses for their identity records while
// ai_discovery.include_user_email is on, and nil otherwise, so turning the
// option off drops them at the next cycle.
func enterpriseWindowsConnectorEmails(stderr io.Writer, cfg *config.Config, manifest enterprisehooks.Manifest) map[string]map[string]string {
	if cfg == nil || !cfg.StandaloneEnterprise() || !cfg.AIDiscovery.IncludeUserEmail {
		return nil
	}
	return enterprisehooks.WindowsConnectorEmails(manifest, func(format string, args ...any) {
		fmt.Fprintf(stderr, format+"\n", args...)
	})
}

// runEnterpriseWindowsEnumerateInterval is the interval-loop entry.
// Runs the first cycle after `initial_delay`, then
// every `interval` thereafter. ctx-cancel (SCM stop) returns within
// a bounded window.
func runEnterpriseWindowsEnumerateInterval(
	ctx context.Context,
	stderr io.Writer,
	opts *enterpriseWindowsEnumerateOptions,
	manifestPath string,
) error {
	// The gateway's MCP admission scan starts an enrolled user's server
	// as that user through this service (#1164).
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	go serveEnterpriseWindowsMCPAsUser(serveCtx, stderr, manifestPath)

	// Initial cycle after the configurable delay (default 30 s)
	// so gateway + guardian publish their startup lines first.
	initial := time.NewTimer(opts.initialDelay)
	defer initial.Stop()

	select {
	case <-ctx.Done():
		return nil
	case <-initial.C:
	}
	// First cycle: log the outcome but do NOT bail on a transient
	// "config missing" error — the loop must
	// tolerate deferred-config boots.
	//
	// Each tick publishes (parity with macOS render-targets.sh): it
	// auto-authorizes newly-discovered (SID, Connector) rows whose
	// per-user profile contains a supported CLI (see
	// internal/enterprisehooks/agent_version_windows.go). Rows
	// without a discoverable CLI are silently skipped. The
	// byte-identical short-circuit in WriteTargetsManifestAtomic
	// keeps steady-state ticks free of fsnotify wakes.
	if err := runEnterpriseWindowsEnumerateSingleCycle(ctx, stderr, manifestPath); err != nil {
		if !isEnterpriseWindowsEnumerateConfigMissing(err) {
			fmt.Fprintf(stderr, "[hook-enumerator] initial cycle failed: %v\n", err)
		}
	}

	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	// Claude Code and Kiro MCP servers are published between cycles too, so a server
	// a user adds reaches install admission within a minute (GAP-0424, GAP-1468).
	mcpRefresh := time.NewTicker(enterpriseWindowsClaudeMCPSpoolInterval)
	defer mcpRefresh.Stop()
	// A sign-in (forwarded by the standalone service host through
	// internal/winsession; never fires otherwise) runs one extra cycle after
	// a settle delay, so a newly signed-in user is enrolled without waiting
	// for the next interval tick.
	// Sign-ins received while the window is armed join it, so a stream of
	// sign-ins cannot postpone the cycle forever. A nil channel never fires,
	// so the window is idle until the first sign-in.
	var session <-chan time.Time
	var lastLogon time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-winsession.Logons():
			lastLogon = enterpriseWindowsEnumerateSessionNow()
			if session == nil {
				session = enterpriseWindowsEnumerateSessionSettleAfter(enterpriseWindowsEnumerateSessionSettle)
			}
		case <-session:
			session = nil
			// A sign-in that joined the window late has not had its settle
			// time yet: its profile may still be incomplete. Run the cycle for
			// the earlier sign-ins and arm one more window for the rest.
			if remaining := enterpriseWindowsEnumerateSessionSettle -
				enterpriseWindowsEnumerateSessionNow().Sub(lastLogon); remaining > 0 {
				session = enterpriseWindowsEnumerateSessionSettleAfter(remaining)
			}
			fmt.Fprintf(stderr, "[hook-enumerator] session sign-in: running an extra cycle\n")
			if err := runEnterpriseWindowsEnumerateSingleCycle(ctx, stderr, manifestPath); err != nil {
				if !isEnterpriseWindowsEnumerateConfigMissing(err) {
					fmt.Fprintf(stderr, "[hook-enumerator] cycle failed: %v\n", err)
				}
			}
		case <-mcpRefresh.C:
			_ = enterpriseWindowsMCPRefresh.Run(ctx, func() error { return refreshEnterpriseWindowsMCPServers(stderr, manifestPath) })
		case <-enterpriseWindowsEnumeratePrivateWalkLate():
			// A profile's private-install walk outlasted its share of the
			// last cycle and has now finished: publish the account as
			// inspected without waiting for the next tick (GAP-2002).
			fmt.Fprintf(stderr, "[hook-enumerator] a slow profile scan finished: running an extra cycle\n")
			if err := runEnterpriseWindowsEnumerateSingleCycle(ctx, stderr, manifestPath); err != nil {
				if !isEnterpriseWindowsEnumerateConfigMissing(err) {
					fmt.Fprintf(stderr, "[hook-enumerator] cycle failed: %v\n", err)
				}
			}
		case <-ticker.C:
			if err := runEnterpriseWindowsEnumerateSingleCycle(ctx, stderr, manifestPath); err != nil {
				if !isEnterpriseWindowsEnumerateConfigMissing(err) {
					fmt.Fprintf(stderr, "[hook-enumerator] cycle failed: %v\n", err)
				}
			}
		}
	}
}

// enterpriseWindowsMCPAsUserRetry is how long the as-user scan server waits
// before it serves again after its pipe failed.
var enterpriseWindowsMCPAsUserRetry = 30 * time.Second

// enterpriseWindowsMCPAsUserServe is the pipe server seam.
var enterpriseWindowsMCPAsUserServe = mcpasuser.Serve

// serveEnterpriseWindowsMCPAsUser serves the gateway's as-user MCP scans
// (#1164) until ctx ends: the standalone profile only (the Secure Client
// profile gateway has no enrolled-user watcher), for the gateway service the
// service environment names. The starter reads the enrollment and the
// published records again for every request. The same pipe serves the
// gateway's refresh before an MCP tool call: the enrolled users' servers are
// published again from their files, so the call is decided on the
// definition the user has now (GAP-0216).
func serveEnterpriseWindowsMCPAsUser(ctx context.Context, stderr io.Writer, manifestPath string) {
	if !managed.IsStandaloneProfile(managed.NormalizeEnterpriseProfile(os.Getenv(managed.EnterpriseProfileEnv))) {
		return
	}
	gatewayService := strings.TrimSpace(os.Getenv(mcpasuser.GatewayServiceEnv))
	if gatewayService == "" {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN %s is not set; MCP servers in user profiles cannot be scanned as their users\n", mcpasuser.GatewayServiceEnv)
		return
	}
	starter := enterprisehooks.WindowsMCPAsUserStarter{
		Manifest: func() (enterprisehooks.Manifest, error) { return enterprisehooks.LoadManifest(manifestPath) },
		AuthorizationDir: func() (string, error) {
			cfg, err := enterpriseWindowsEnumerateConfigLoader()
			if err != nil {
				return "", fmt.Errorf("load config: %w", err)
			}
			if !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() {
				return "", errors.New("this deployment does not scan enrolled users' MCP servers")
			}
			return managed.HookGuardianAuthorizationDir(cfg.DataDir), nil
		},
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	refresh := func(ctx context.Context) error {
		return enterpriseWindowsMCPRefresh.Run(ctx, func() error { return refreshEnterpriseWindowsMCPServers(stderr, manifestPath) })
	}
	for {
		err := enterpriseWindowsMCPAsUserServe(ctx, gatewayService, refresh, starter.Start, logf)
		if ctx.Err() != nil {
			return
		}
		fmt.Fprintf(stderr, "[hook-enumerator] WARN MCP as-user scan server stopped: %v; retrying in %s\n", err, enterpriseWindowsMCPAsUserRetry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(enterpriseWindowsMCPAsUserRetry):
		}
	}
}

// enterpriseWindowsClaudeMCPSpoolInterval is how often the Claude Code and Kiro MCP
// servers of enrolled users are published between enumeration cycles.
const enterpriseWindowsClaudeMCPSpoolInterval = 30 * time.Second

// enterpriseWindowsMCPPublishMu serializes the publications: the interval
// loop and the gateway's refreshes through the as-user pipe write the same
// records.
var enterpriseWindowsMCPPublishMu sync.Mutex

// enterpriseWindowsMCPRefresh shares one publication among the refreshes
// that wait for it (mcpasuser.Coalescer).
var enterpriseWindowsMCPRefresh mcpasuser.Coalescer

// publishEnterpriseWindowsMCPServers publishes the Claude Code and Kiro MCP
// servers of the users manifest enrolls for the gateway, whose service
// account cannot read ~/.claude.json (GAP-0424) nor a protected
// ~/.kiro/settings/mcp.json (GAP-1468). Standalone only: the Secure Client
// profile gateway has no enrolled-user watcher. When something was not
// published (also logged) it returns a *mcpasuser.RefreshIncomplete that
// names, per connector, the records it could not publish, or the connector
// whose record folder could not be written: the gateway reads the records
// that were published and refuses only the calls of what it names, so one
// user's failed record does not refuse other users' or other connectors'
// calls.
func publishEnterpriseWindowsMCPServers(cfg *config.Config, manifest enterprisehooks.Manifest, stderr io.Writer) error {
	if cfg == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() {
		return nil
	}
	enterpriseWindowsMCPPublishMu.Lock()
	defer enterpriseWindowsMCPPublishMu.Unlock()
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	authorizationDir := managed.HookGuardianAuthorizationDir(cfg.DataDir)
	var errs []error
	incomplete := &mcpasuser.RefreshIncomplete{}
	for _, spool := range []struct {
		connector, label, dir string
		write                 func(string, enterprisehooks.Manifest, func(string) error, func(string, ...any)) error
	}{
		{"claudecode", "Claude Code", enterprisehooks.ClaudeMCPSpoolDir(authorizationDir), enterpriseWindowsClaudeMCPSpoolWriter},
		{"kiro", "Kiro", enterprisehooks.KiroMCPSpoolDir(authorizationDir), enterpriseWindowsKiroMCPSpoolWriter},
	} {
		err := spool.write(spool.dir, manifest, enterpriseHookAuthorizationOwnershipSetter, logf)
		if err == nil {
			continue
		}
		fmt.Fprintf(stderr, "[hook-enumerator] WARN could not publish %s MCP servers: %v\n", spool.label, err)
		errs = append(errs, fmt.Errorf("publish %s MCP servers: %w", spool.label, err))
		records, whole := enterprisehooks.MCPSpoolRecordFailures(err)
		if whole {
			incomplete.Connectors = append(incomplete.Connectors, spool.connector)
			continue
		}
		for _, record := range records {
			incomplete.Records = append(incomplete.Records, mcpasuser.RefreshRecord{Connector: spool.connector, SID: record.SID, Home: record.Home})
		}
	}
	if len(errs) == 0 {
		return nil
	}
	incomplete.Detail = errors.Join(errs...).Error()
	return incomplete
}

// publishEnterpriseWindowsIDEAppData publishes the IDE inventory of each
// enrolled profile whose AppData folder redirection moved, which the gateway
// service cannot read (enterprisehooks.WriteWindowsIDEAppDataSpool,
// GAP-1249). Standalone with AI discovery on only: the Secure Client profile
// gateway has no IDE inventory.
func publishEnterpriseWindowsIDEAppData(cfg *config.Config, manifest enterprisehooks.Manifest, stderr io.Writer) {
	if cfg == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() || !cfg.AIDiscovery.Enabled {
		return
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	dir := enterprisehooks.IDEAppDataSpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	if err := enterpriseWindowsIDEAppDataSpoolWriter(dir, manifest, enterpriseHookAuthorizationOwnershipSetter, logf); err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN could not publish the IDE inventory of redirected AppData: %v\n", err)
	}
}

// refreshEnterpriseWindowsMCPServers republishes them from the last
// published manifest. The error says why nothing was published; a
// deployment that publishes no MCP servers has nothing to refresh.
func refreshEnterpriseWindowsMCPServers(stderr io.Writer, manifestPath string) error {
	cfg, err := enterpriseWindowsEnumerateConfigLoader()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	manifest, err := enterprisehooks.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("load the enrollment manifest: %w", err)
	}
	return publishEnterpriseWindowsMCPServers(cfg, manifest, stderr)
}

// enumerationLoggerForStderr wraps the enumerator's per-drop logger
// callback so drops surface on the same stderr the interval-loop
// summary lines use.
func enumerationLoggerForStderr(w io.Writer) enterprisehooks.EnumerationLogger {
	return func(subject, reason string) {
		fmt.Fprintf(w, "[hook-enumerator] skipped %s: %s\n", subject, reason)
	}
}

// countDistinctSIDs is a small helper for the summary log — a cycle
// emitting 10 targets across 5 users is more informative than "10
// targets" alone.
func countDistinctSIDs(targets []enterprisehooks.ManifestTarget) int {
	seen := make(map[string]struct{})
	for _, t := range targets {
		if sid := strings.TrimSpace(t.SID); sid != "" {
			seen[strings.ToUpper(sid)] = struct{}{}
		}
	}
	return len(seen)
}

// enterpriseWindowsEnumerateConfigLoader is the config-load seam the
// interval-loop uses. Points at the SAME administrator-owned config
// path the gateway + guardian read, via the same helper the
// deferred-config wait uses. Test hooks reassign this to a fixture.
var enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
	return enterpriseHooksWindowsConfigLoader()
}

var (
	enterpriseWindowsEnumerateProfileEnumerator = enterprisehooks.EnumerateWindows
	enterpriseWindowsEnumerateManifestWriter    = enterprisehooks.WriteTargetsManifestAtomic
	// Standalone only: the enrollment group cache and the unprotected-agents
	// record beside the manifest.
	enterpriseWindowsEnumerateGroupCacheLoader   = enterprisehooks.LoadWindowsEnrollmentGroupCache
	enterpriseWindowsEnumerateGroupCacheWriter   = enterprisehooks.SaveWindowsEnrollmentGroupCache
	enterpriseWindowsIdentitySpoolWriter         = enterprisehooks.WriteWindowsIdentitySpool
	enterpriseWindowsClaudeMCPSpoolWriter        = enterprisehooks.WriteWindowsClaudeMCPSpool
	enterpriseWindowsKiroMCPSpoolWriter          = enterprisehooks.WriteWindowsKiroMCPSpool
	enterpriseWindowsIDEAppDataSpoolWriter       = enterprisehooks.WriteWindowsIDEAppDataSpool
	enterpriseWindowsManifestGroupCacheRefresher = enterprisehooks.RefreshWindowsManifestIdentityGroups
	enterpriseWindowsEnumerateUnprotectedWriter  = enterprisehooks.WriteWindowsUnprotectedAgents
	// enterpriseWindowsInventoryReadRevoker takes the gateway's inventory
	// ACEs from the profiles a cycle stopped enrolling.
	enterpriseWindowsInventoryReadRevoker = enterprisehooks.RevokeGatewayInventoryReadForManifest
	// The grant ledger beside the manifest.
	enterpriseWindowsInventoryGrantLedgerLoader = enterprisehooks.LoadWindowsInventoryGrantLedger
	enterpriseWindowsInventoryGrantLedgerSaver  = enterprisehooks.SaveWindowsInventoryGrantLedger
)

// isEnterpriseWindowsEnumerateConfigMissing recognises the specific
// "config.yaml is not on disk yet" error so the interval loop can
// treat it as a soft-retry rather than a hard failure, matching the
// deferred-config posture of the gateway and guardian.
//
// Detection is `errors.Is(err, fs.ErrNotExist)` first — both
// config.LoadFromFile and the Windows trusted-path validator wrap
// their underlying os.Open / os.Lstat errors with %w, so the fs
// sentinel survives the wrap chain. The substring fallback stays
// for edge cases where a caller loses the chain (e.g. a test
// harness that stringifies the error before passing it up). A
// message-only check would fail
// on non-English Windows locales where the OS returns a localized
// "cannot find the file" string.
func isEnterpriseWindowsEnumerateConfigMissing(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "cannot find the file specified") ||
		strings.Contains(msg, "The system cannot find the file specified")
}

// standaloneWindowsEnumerateOptions adds the standalone profile's enrollment
// filters to an enumeration: include_users is additive, exclude_users drops
// a profile, and exempt_users keeps only its machine-policy rows so it is
// inspected instead of failing closed as unregistered. Secure Client options
// are returned unchanged.
func standaloneWindowsEnumerateOptions(cfg *config.Config, opts enterprisehooks.EnumerateOptions) enterprisehooks.EnumerateOptions {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return opts
	}
	enrollment := cfg.Enterprise.Enrollment
	opts.IncludeUsers = append([]string(nil), enrollment.IncludeUsers...)
	opts.ExcludeUsers = append([]string(nil), enrollment.ExcludeUsers...)
	opts.ExemptUsers = append([]string(nil), enrollment.ExemptUsers...)
	opts.IncludeGroups = append([]string(nil), enrollment.IncludeGroups...)
	opts.ExcludeGroups = append([]string(nil), enrollment.ExcludeGroups...)
	return opts
}

// standaloneWindowsEnumerateIdleReason reports why a standalone enumerator
// cycle must not publish: enterprise.enrollment.mode manifest hands
// targets.yaml to the administrator, as on Linux and macOS.
func standaloneWindowsEnumerateIdleReason(cfg *config.Config) string {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(cfg.Enterprise.Enrollment.Mode), config.EnterpriseEnrollmentManifest) {
		return "enterprise.enrollment.mode is manifest; the administrator publishes targets"
	}
	return ""
}
