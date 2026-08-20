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
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseWindowsEnumerateDefaultInterval is the SCM-service
// default sleep between cycles. Matches macOS's
// `com.cisco.secureclient.defenseclaw.hook-enumerator` LaunchDaemon
// `StartInterval = 300` (5 minutes).
const enterpriseWindowsEnumerateDefaultInterval = 5 * time.Minute

// enterpriseWindowsEnumerateInitialCycleDelay bounds the "first
// cycle" wait so a `--deferred-config` fresh-install install path
// doesn't have to wait a full 5-minute interval before hooks appear.
// Set to 30 s so the gateway + guardian services publish their
// "starting" health lines FIRST (each takes ~5-10 s on a cold-boot);
// the enumerator's first cycle then runs, and any hooked-in health
// dashboard sees a coherent startup ordering.
//
// Spec 005 REQ-13. Tuneable in a follow-up if telemetry shows this
// is too long / too short.
const enterpriseWindowsEnumerateInitialCycleDelay = 30 * time.Second

// enterpriseWindowsEnumerateCycleTimeout bounds a single enumeration
// cycle so a wedged registry walk / IO can't starve subsequent
// ticks. Spec 005 REQ-19.
const enterpriseWindowsEnumerateCycleTimeout = 60 * time.Second

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
//     service invokes at boot. Sleeps `--interval` (default 5m)
//     between cycles; each cycle is bounded by
//     `enterpriseWindowsEnumerateCycleTimeout`; ctx-cancel
//     (SCM stop signal) returns within a bounded window.
//
// Spec 005 REQ-03, REQ-04, REQ-13, REQ-18, REQ-19.
func newEnterpriseWindowsEnumerateCommand() *cobra.Command {
	opts := &enterpriseWindowsEnumerateOptions{
		interval:     enterpriseWindowsEnumerateDefaultInterval,
		initialDelay: enterpriseWindowsEnumerateInitialCycleDelay,
	}
	cmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Refresh targets.yaml from the current local user profile set",
		Long: `Walk HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList to
discover local user profiles, filter to interactive users (S-1-5-21-…), and
regenerate the hook-guardian's targets.yaml so newly-created user profiles
receive hooks without an administrator invoking 'enterprise windows repair'.

Two modes:

  * default: enter an interval-loop suitable for an SCM ImagePath.
    Sleeps --interval (default 5m) between cycles; the first cycle
    fires within 30 s of service start so a deferred-config install
    does not wait a full interval for hooks to appear.

  * --once: run a single cycle synchronously and exit. Used by the
    fresh-install path to seed targets.yaml before the enumerator
    service is up.

The DACL discipline on targets.yaml is unchanged from spec 003 —
the enumerator writes as LocalSystem via SYSTEM's inherited
FullControl, matching the guardian's account model.

Managed-enterprise Windows only. macOS's LaunchDaemon-based
'hook-enumerator' + render-targets.sh already covers the darwin
side; nothing about this subcommand is invoked on non-Windows OSes.
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

// runEnterpriseWindowsEnumerateSingleCycle runs one bounded cycle
// and returns. Used by both `--once` and the interval-loop's
// tick handler.
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

	logf := enumerationLoggerForStderr(stderr)
	start := time.Now()
	manifest, err := enterprisehooks.EnumerateWindows(cycleCtx, cfg, enterprisehooks.EnumerateOptions{
		ExistingManifestPath: manifestPath,
		Logger:               logf,
	})
	if err != nil {
		return fmt.Errorf("enterprise windows enumerate: walk profiles: %w", err)
	}

	changed, err := enterprisehooks.WriteTargetsManifestAtomic(manifestPath, manifest)
	if err != nil {
		return fmt.Errorf("enterprise windows enumerate: write manifest: %w", err)
	}
	elapsed := time.Since(start)

	fmt.Fprintf(stderr, "[hook-enumerator] cycle complete users=%d targets=%d changed=%t elapsed=%s\n",
		countDistinctSIDs(manifest.Targets), len(manifest.Targets), changed, elapsed)
	if elapsed > 10*time.Second {
		// Spec 005 REQ-19 documents a soft 10 s target on a 100-user
		// fleet; log a WARN if a single cycle overshoots so operators
		// see the degradation before the hard 60 s ceiling fires.
		fmt.Fprintf(stderr, "[hook-enumerator] WARN cycle exceeded 10 s target: %s\n", elapsed)
	}
	return nil
}

// runEnterpriseWindowsEnumerateInterval is the interval-loop entry.
// Runs the first cycle after `initial_delay` (per REQ-13), then
// every `interval` thereafter. ctx-cancel (SCM stop) returns within
// a bounded window.
func runEnterpriseWindowsEnumerateInterval(
	ctx context.Context,
	stderr io.Writer,
	opts *enterpriseWindowsEnumerateOptions,
	manifestPath string,
) error {
	// Initial cycle after the configurable delay. REQ-13 default 30 s
	// so gateway + guardian publish their startup lines first.
	initial := time.NewTimer(opts.initialDelay)
	defer initial.Stop()

	select {
	case <-ctx.Done():
		return nil
	case <-initial.C:
	}
	// First cycle: log the outcome but do NOT bail on a transient
	// "config missing" error — the whole point of REQ-04 is to
	// tolerate deferred-config boots.
	if err := runEnterpriseWindowsEnumerateSingleCycle(ctx, stderr, manifestPath); err != nil {
		if !isEnterpriseWindowsEnumerateConfigMissing(err) {
			fmt.Fprintf(stderr, "[hook-enumerator] initial cycle failed: %v\n", err)
		}
	}

	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := runEnterpriseWindowsEnumerateSingleCycle(ctx, stderr, manifestPath); err != nil {
				if !isEnterpriseWindowsEnumerateConfigMissing(err) {
					fmt.Fprintf(stderr, "[hook-enumerator] cycle failed: %v\n", err)
				}
			}
		}
	}
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
// path the gateway + guardian read, via the same helper spec 003
// wired in. Test hooks reassign this to a fixture.
var enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
	return enterpriseHooksWindowsConfigLoader()
}

// isEnterpriseWindowsEnumerateConfigMissing recognises the specific
// "config.yaml is not on disk yet" error so the interval loop can
// treat it as a soft-retry rather than a hard failure. Spec 003
// added the deferred-config posture; the enumerator's REQ-04 mirrors
// it.
//
// Detection is `errors.Is(err, fs.ErrNotExist)` first — both
// config.LoadFromFile and the Windows trusted-path validator wrap
// their underlying os.Open / os.Lstat errors with %w, so the fs
// sentinel survives the wrap chain. The substring fallback stays
// for edge cases where a caller loses the chain (e.g. a test
// harness that stringifies the error before passing it up). See CR
// spec-005:PRRT_kwDORuAK-s6atyfG — a message-only check would fail
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
