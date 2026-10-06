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
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// unixLifecycleOptions are the flags of `enterprise linux|macos <action>`.
type unixLifecycleOptions struct {
	payload              string
	fromPackage          bool
	config               string
	noStart              bool
	adoptExisting        bool
	allowDowngrade       bool
	purge                bool
	removeServiceAccount bool
	keepState            bool
	keepServiceAccount   bool
	productVersion       string
	reason               string
	lockWait             time.Duration
	json                 bool
}

// enterpriseSecretOptions are the flags of `enterprise secret <action>`.
type enterpriseSecretOptions struct {
	name      string
	fromStdin bool
	fromFile  string
	json      bool
	// lockWait is how long set and remove wait for another lifecycle run
	// (Linux and macOS).
	lockWait time.Duration
}

var (
	enterpriseLinuxCmd = newUnixLifecycleGroup("linux", "Linux (systemd)")
	enterpriseMacOSCmd = newUnixLifecycleGroup("macos", "macOS (launchd)")

	enterpriseSecretCmd = &cobra.Command{
		Use:   "secret",
		Short: "Manage protected credentials of a standalone managed deployment",
		Long: `Store, inspect or remove the protected credentials a standalone managed
deployment reads:

  - the Cisco AI Defense API key named by
    enterprise.inspection.ai_defense.credential;
  - observability destination credentials named by a header value
    {credential: NAME} (otlp, http_jsonl), token_credential (splunk_hec)
    or bearer_credential (http_jsonl).

Values are read from standard input or a file and are never printed.
Status shows only presence, modification time and a digest prefix.`,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	}
)

func newUnixLifecycleGroup(name, platform string) *cobra.Command {
	group := &cobra.Command{
		Use:   name,
		Short: "Manage the standalone managed-enterprise deployment on " + platform,
		Long: `Install, upgrade, repair, reconcile, inspect, verify or remove the standalone
managed-enterprise DefenseClaw deployment on ` + platform + `.

Every mutating action is a transaction: it takes the lifecycle lock,
snapshots what it will change, applies, activates the services in
dependency order, verifies, and rolls back on any failure. Run as root
from an administrator shell, a package script or an MDM agent.

Exit codes: 0 success or no-op, 1 failure (rolled back), 2 invalid
arguments, 75 another lifecycle run holds the lock.`,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		// An action the group does not know is invalid arguments (exit 2),
		// not a silent help page.
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				// The suggestion, usage and --help lines every other gateway
				// group prints for a mistyped subcommand (GAP-2374).
				return lifecycleFlagError(cmd, fmt.Errorf("unknown action %q for %q%s", args[0], cmd.CommandPath(), didYouMean(cmd, args[0])))
			}
			return cmd.Help()
		},
	}
	group.SetFlagErrorFunc(lifecycleFlagError)
	summaries := map[string]string{
		"install":            "Install the deployment (refuses when one is already installed)",
		"upgrade":            "Upgrade an installed deployment from a new payload or package",
		"repair":             "Re-apply the installed deployment's files, modes and services (restarts the services)",
		"ensure":             "Install, upgrade or repair as needed; a no-op when nothing changed",
		"reconcile":          "Run one immediate hook guardian reconcile",
		"rotate-credentials": "Rotate the per-user credential key, moving every user before the new key takes effect",
		"status":             "Report the deployment state (read-only)",
		"verify":             "Verify every file, permission, service and readiness check (read-only)",
		"uninstall":          "Stop and remove the deployment, its machine state and every account's hooks (each account keeps ~/.defenseclaw); --purge removes everything",
	}
	for _, action := range []string{"install", "upgrade", "repair", "ensure", "reconcile", "rotate-credentials", "status", "verify", "uninstall"} {
		group.AddCommand(newUnixLifecycleCommand(name, action, summaries[action]))
	}
	group.AddCommand(newUnixDiscoveryCommand(name))
	group.AddCommand(newEnterpriseIdentityViewCommands(name)...)
	return group
}

// lockWaitUsage documents --lock-wait on every action that takes the
// lifecycle lock.
const lockWaitUsage = "wait up to this long for another lifecycle run (default 5s, at most 15m) before exiting 75"

// lockWaitValue is --lock-wait: a duration that keeps the text as typed, so
// the cap error names "1h", not "60m", and whose malformed-value error gives
// examples inside the cap (GAP-2329).
type lockWaitValue struct {
	wait  *time.Duration
	typed string
}

func (v *lockWaitValue) Set(s string) error {
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*v.wait, v.typed = d, s
	return nil
}

func (v *lockWaitValue) Type() string { return "duration" }

// String is "0" when unset, so --help prints no "(default 0s)".
func (v *lockWaitValue) String() string {
	if v.wait == nil || *v.wait == 0 {
		return "0"
	}
	return v.wait.String()
}

func (v *lockWaitValue) flagTakes() string { return "a duration from 0 to 15m, such as 30s or 5m" }

func addLockWaitFlag(flags *pflag.FlagSet, wait *time.Duration) {
	flags.Var(&lockWaitValue{wait: wait}, "lock-wait", lockWaitUsage)
}

// typedLockWait is --lock-wait as typed when it was typed as wait, or "".
func typedLockWait(cmd *cobra.Command, wait time.Duration) string {
	if f := cmd.Flags().Lookup("lock-wait"); f != nil {
		if v, ok := f.Value.(*lockWaitValue); ok && v.typed != "" && *v.wait == wait {
			return v.typed
		}
	}
	return ""
}

// lifecycleNoArgs rejects a stray positional argument with the wording of
// every other gateway command ("unexpected argument", GAP-2330) and the
// lifecycle's invalid-arguments exit code.
func lifecycleNoArgs(cmd *cobra.Command, args []string) error {
	if err := strayArgumentError(cmd, args); err != nil {
		return lifecycleFlagError(cmd, err)
	}
	return nil
}

func newUnixLifecycleCommand(platform, action, summary string) *cobra.Command {
	opts := &unixLifecycleOptions{}
	cmd := &cobra.Command{
		Use:          action,
		Short:        summary,
		SilenceUsage: true,
		Args:         lifecycleNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnixLifecycle(cmd, platform, action, opts)
		},
	}
	// status and verify take no --lock-wait, so their help says how they
	// wait for another lifecycle run (GAP-2409).
	switch action {
	case "verify":
		cmd.Long = summary + ".\n\nverify first waits up to 5s for another lifecycle run to finish. If that run is still going, it checks nothing and exits 75 (lifecycle_busy)."
	case "status":
		cmd.Long = summary + ".\n\nRun as root, status first waits up to 5s for another lifecycle run to finish. If that run is still going, it reports the installed version, checks nothing else and exits 75 (lifecycle_busy)."
	}
	// An unknown flag or a malformed value fails before RunE; the documented
	// exit code for it is invalid arguments, not cobra's generic 1.
	cmd.SetFlagErrorFunc(lifecycleFlagError)
	flags := cmd.Flags()
	switch action {
	case "install", "upgrade", "repair", "ensure":
		flags.StringVar(&opts.payload, "payload", "", "absolute directory holding the staged binaries to install")
		flags.BoolVar(&opts.fromPackage, "from-package", false, "use the binaries the defenseclaw-enterprise package installed")
		flags.StringVar(&opts.config, "config", "", "absolute path of the administrator config to install")
		flags.BoolVar(&opts.noStart, "no-start", false, "install without starting the services")
		flags.StringVar(&opts.productVersion, "product-version", "", "refuse unless the payload is exactly this version")
		flags.BoolVar(&opts.allowDowngrade, "allow-downgrade", false, "allow installing a version older than the installed one (deliberate rollback)")
		if action == "install" || action == "ensure" {
			flags.BoolVar(&opts.adoptExisting, "adopt-existing", false, "back up and take over an unmanaged DefenseClaw layout")
		}
		if action == "ensure" {
			flags.StringVar(&opts.reason, "reason", "", "why ensure runs (recorded in the result)")
		}
		addLockWaitFlag(flags, &opts.lockWait)
	case "uninstall":
		flags.BoolVar(&opts.purge, "purge", false, "also remove each enrolled account's ~/.defenseclaw, the empty agent folders DefenseClaw created in its home, its per-user binaries in ~/.local/bin and DefenseClaw's entries in its uv cache ~/.cache/uv (after stopping its per-user gateway); the result names every enrolled account whose data it removed, and warns for each one whose data it kept; accounts the deployment never enrolled have no DefenseClaw per-user data and are not listed")
		flags.BoolVar(&opts.keepState, "keep-state", false, "keep the machine state (config, secrets, gateway and guardian state, logs, lifecycle state) and the service account, so a reinstall resumes with them; without it uninstall removes all of it")
		flags.BoolVar(&opts.keepServiceAccount, "keep-service-account", false, "keep the gateway service account, which uninstall deletes otherwise")
		flags.BoolVar(&opts.removeServiceAccount, "remove-service-account", false, "deprecated: uninstall deletes the gateway service account by default; removed in the next minor release")
		addLockWaitFlag(flags, &opts.lockWait)
	case "reconcile", "rotate-credentials":
		addLockWaitFlag(flags, &opts.lockWait)
	}
	flags.BoolVar(&opts.json, "json", false, "print the lifecycle result as JSON")
	return cmd
}

// invalidLifecycleArguments labels err with the lifecycle's invalid-arguments
// exit code (2 on Linux and macOS; 1639 where Windows runs these groups).
func invalidLifecycleArguments(err error) error {
	return withExitCode(err, enterprisestatus.InvalidArgsExitCode(runtime.GOOS))
}

// lifecycleFlagError reports an unknown flag, a malformed value or a stray
// argument with the usage line and the --help pointer every other gateway
// command prints (GAP-1549, GAP-1943), and the lifecycle's documented
// invalid-arguments exit code.
func lifecycleFlagError(c *cobra.Command, err error) error {
	if c == nil || err == nil {
		return invalidLifecycleArguments(err)
	}
	return invalidLifecycleArguments(&delegatedUsageError{msg: usageMessage(c, err), err: err})
}

func newEnterpriseSecretCommand(action, summary string) *cobra.Command {
	opts := &enterpriseSecretOptions{}
	cmd := &cobra.Command{
		Use:          action,
		Short:        summary,
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseSecret(cmd, action, opts)
		},
	}
	if action != "status" {
		cmd.Flags().StringVar(&opts.name, "name", "", "credential name (lowercase letters, digits and dashes)")
		_ = cmd.MarkFlagRequired("name")
	}
	if action == "set" {
		cmd.Flags().BoolVar(&opts.fromStdin, "from-stdin", false, "read the value from standard input")
		cmd.Flags().StringVar(&opts.fromFile, "from-file", "", "read the value from this file")
	}
	if action != "status" && runtime.GOOS != "windows" {
		addLockWaitFlag(cmd.Flags(), &opts.lockWait)
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "print JSON")
	if runtime.GOOS != "windows" {
		// An unknown flag, a malformed value, a stray argument or a missing
		// --name is invalid arguments: exit 2 with the usage line and the
		// --help pointer, as on enterprise linux|macos (GAP-2095).
		cmd.SetFlagErrorFunc(lifecycleFlagError)
		cmd.Args = lifecycleNoArgs
		cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
			if err := cmd.ValidateRequiredFlags(); err != nil {
				return lifecycleFlagError(cmd, err)
			}
			return nil
		}
	}
	return cmd
}

func init() {
	enterpriseSecretCmd.AddCommand(
		newEnterpriseSecretCommand("set", "Store a protected credential and apply it"),
		newEnterpriseSecretCommand("status", "List protected credentials without revealing values"),
		newEnterpriseSecretCommand("remove", "Remove a protected credential and apply the change"),
	)
	enterpriseCmd.AddCommand(enterpriseLinuxCmd, enterpriseMacOSCmd, enterpriseSecretCmd)
}

// writeLifecycleSummary prints a short human-readable result. A result
// with warnings never gets the green check: the headline says how many
// there are.
func writeLifecycleSummary(w io.Writer, action string, ok, noop bool, noopReason string, errs, warns []string) {
	switch {
	case ok && noop && len(warns) > 0:
		fmt.Fprintf(w, "! %s: nothing to do (%s), %s\n", action, noopReason, countNoun(len(warns), "warning"))
	case ok && noop:
		fmt.Fprintf(w, "✓ %s: nothing to do (%s)\n", action, noopReason)
	case ok && len(warns) > 0:
		fmt.Fprintf(w, "! %s: done with %s\n", action, countNoun(len(warns), "warning"))
	case ok:
		fmt.Fprintf(w, "✓ %s: done\n", action)
	default:
		fmt.Fprintf(w, "✗ %s failed\n", action)
	}
	for _, warning := range warns {
		fmt.Fprintf(w, "  ! %s\n", warning)
	}
	for _, e := range errs {
		fmt.Fprintf(w, "  ✗ %s\n", e)
	}
}

func joinMessages(parts []string) string { return strings.Join(parts, "; ") }

func countNoun(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", count, noun)
}
