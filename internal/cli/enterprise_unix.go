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
				return invalidLifecycleArguments(fmt.Errorf("unknown action %q for %q; run %q for the actions", args[0], cmd.CommandPath(), cmd.CommandPath()+" --help"))
			}
			return cmd.Help()
		},
	}
	group.SetFlagErrorFunc(lifecycleFlagError)
	summaries := map[string]string{
		"install":            "Install the deployment (refuses when one is already installed)",
		"upgrade":            "Upgrade an installed deployment from a new payload or package",
		"repair":             "Re-apply the installed deployment's files, modes and services",
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
	return group
}

// lockWaitUsage documents --lock-wait on every action that takes the
// lifecycle lock.
const lockWaitUsage = "wait up to this long for another lifecycle run (default 5s, at most 15m) before exiting 75"

func newUnixLifecycleCommand(platform, action, summary string) *cobra.Command {
	opts := &unixLifecycleOptions{}
	cmd := &cobra.Command{
		Use:          action,
		Short:        summary,
		SilenceUsage: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return lifecycleFlagError(cmd, err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnixLifecycle(cmd, platform, action, opts)
		},
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
		flags.DurationVar(&opts.lockWait, "lock-wait", 0, lockWaitUsage)
	case "uninstall":
		flags.BoolVar(&opts.purge, "purge", false, "also remove each enrolled account's ~/.defenseclaw, the empty agent folders DefenseClaw created in its home, and its per-user binaries in ~/.local/bin (after stopping its per-user gateway); the result names every enrolled account whose data it removed, and warns for each one whose data it kept; accounts the deployment never enrolled have no DefenseClaw per-user data and are not listed")
		flags.BoolVar(&opts.keepState, "keep-state", false, "keep the machine state (config, secrets, gateway and guardian state, logs, lifecycle state) and the service account, so a reinstall resumes with them; without it uninstall removes all of it")
		flags.BoolVar(&opts.keepServiceAccount, "keep-service-account", false, "keep the gateway service account, which uninstall deletes otherwise")
		flags.BoolVar(&opts.removeServiceAccount, "remove-service-account", false, "delete the gateway service account (the default now; kept for older scripts)")
		flags.DurationVar(&opts.lockWait, "lock-wait", 0, lockWaitUsage)
	case "reconcile", "rotate-credentials":
		flags.DurationVar(&opts.lockWait, "lock-wait", 0, lockWaitUsage)
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
		cmd.Flags().DurationVar(&opts.lockWait, "lock-wait", 0, lockWaitUsage)
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "print JSON")
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
