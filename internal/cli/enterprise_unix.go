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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// unixLifecycleOptions are the flags of `enterprise linux|macos <action>`.
type unixLifecycleOptions struct {
	payload            string
	fromPackage        bool
	config             string
	noStart            bool
	adoptExisting      bool
	allowDowngrade     bool
	purge              bool
	keepState          bool
	keepServiceAccount bool
	productVersion     string
	reason             string
	lockWait           time.Duration
	json               bool
}

// enterpriseSecretOptions are the flags of `enterprise secret <action>`.
type enterpriseSecretOptions struct {
	name      string
	fromStdin bool
	fromFile  string
	// bundle is the signed policy bundle that binds a new value (set
	// --bundle): a credential the confirmed bundle binds rotates only to a
	// value a newer verified bundle signs.
	bundle string
	// ifConfirmed (set --bundle --if-confirmed) stores the value only while
	// the confirmed policy bundle has this manifest SHA-256 ("none": no
	// bundle is confirmed). undoRotation (set|remove --undo-rotation) puts
	// back a credential a rotation changed, only while the bundle confirmed
	// before that rotation still is and does not sign the value stored now
	// (checkSecretTransaction). The MDM wrappers journal the
	// confirmed bundle before a rotation and pass it to both; a 1.0.4
	// build reporting secret_set_bundle takes them. undoConfig (remove
	// --undo-rotation --undo-config) is the SHA-256 of the installed config
	// the wrapper journaled before the rotation: the put-back
	// takes a credential the installed config references only while that
	// very config is installed (undoRotationOnConfig).
	ifConfirmed  string
	undoRotation string
	undoConfig   string
	// ifStored is the SHA-256 of the exact value a caller expects now.
	// Windows also accepts "none" for proven absence.
	// It is compared under the credential/lifecycle lock before a change.
	ifStored string
	json     bool
	// lockWait is how long set and remove wait for another lifecycle run
	// (Linux and macOS) or for a policy bundle run to release bundle.lock
	// (Windows).
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
  - the API key of the LLM judge and the skill, MCP and plugin scanners
    named by enterprise.inspection.llm.credential (they never read
    llm.api_key_env or the service environment);
  - observability destination credentials named by a header value
    {credential: NAME} (otlp, http_jsonl), token_credential (splunk_hec)
    or bearer_credential (http_jsonl).

Values are read from standard input or a file and are never printed.
Status shows only presence, modification time and a digest prefix. On Linux and
macOS, check proves the Cisco AI Defense key before the first prompt.`,
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
		"uninstall":          "Stop and remove the deployment, its machine state and every account's hooks (each account keeps ~/.defenseclaw and its sandboxes, and the gateway keeps its registrations of those sandboxes); --purge removes everything",
	}
	for _, action := range []string{"install", "upgrade", "repair", "ensure", "reconcile", "rotate-credentials", "status", "verify", "uninstall"} {
		group.AddCommand(newUnixLifecycleCommand(name, action, summaries[action]))
	}
	group.AddCommand(newUnixDiscoveryCommand(name))
	group.AddCommand(newEnterpriseIdentityViewCommands(name)...)
	if name == "linux" {
		group.AddCommand(newUnixTetragonCommand())
	}
	// `enterprise <os> policy`, as the other administrator views are spelled
	// (GAP-0201, GAP-0240).
	policy, _, _, _ := newEnterprisePolicyGroup(name)
	group.AddCommand(policy)
	return group
}

// sandboxRowsHelp documents the sandbox rows of status and verify.
const sandboxRowsHelp = "\n\nWhen sandboxes are on (openshell.enabled), the services list also has the sandbox rows: the install mode and driver, " +
	"each prerequisite that mode needs (OpenShell, its MicroVM driver, e2fsprogs, Docker or /dev/kvm) as ok or missing with what to run, " +
	"the docker or kvm group membership of the users that run sandboxes, the OpenShell users installed themselves (setup mode: user-installed, unmanaged), " +
	"and the changes waiting for a user's sandboxes to stop (pending). A missing prerequisite is a warning, openshell_prerequisite_missing: " +
	"DefenseClaw itself is healthy, and the gateway refuses the sandbox runs of users until it is fixed. On Linux, with driver vm or auto and " +
	"driver_fallback docker, the docker fallback has its own rows (fallback ...), and a missing MicroVM prerequisite while the fallback is ready " +
	"is the warning openshell_driver_fallback: users get docker sandboxes with every profile floor unchanged."

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
		Args: func(cmd *cobra.Command, args []string) error {
			return lifecycleArgumentError(cmd, action, opts.json, lifecycleNoArgs(cmd, args))
		},
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
		cmd.Long = summary + ".\n\nRun as root, status first waits up to 5s for another lifecycle run to finish. If that run is still going, the change is pending apply, which is not a failure: status reports ok with pending_apply and the installed version, names the run in a lifecycle_busy warning, checks nothing else and exits 75 so you run it again."
	}
	if action == "status" || action == "verify" {
		cmd.Long += sandboxRowsHelp
	}
	// An unknown flag or a malformed value fails before RunE; the documented
	// exit code for it is invalid arguments, not cobra's generic 1.
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return lifecycleArgumentError(c, action, opts.json, lifecycleFlagError(c, err))
	})
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
		flags.BoolVar(&opts.purge, "purge", false, "also remove each enrolled account's ~/.defenseclaw, the empty agent folders DefenseClaw created in its home, its per-user binaries in ~/.local/bin and DefenseClaw's entries in its uv cache ~/.cache/uv (after stopping its per-user gateway); an account's own DefenseClaw install from before the enrollment is kept as it is (a machine uninstall never deletes or moves an account's own data); the result names every enrolled account whose data it removed, and warns for each one whose data it kept; accounts the deployment never enrolled keep their DefenseClaw files, and the result names each one that has any")
		flags.BoolVar(&opts.keepState, "keep-state", false, unixKeepStateUsage(platform))
		flags.BoolVar(&opts.keepServiceAccount, "keep-service-account", false, "keep the gateway service account, which uninstall deletes otherwise")
		addLockWaitFlag(flags, &opts.lockWait)
	case "reconcile", "rotate-credentials":
		addLockWaitFlag(flags, &opts.lockWait)
	}
	flags.BoolVar(&opts.json, "json", false, "print the lifecycle result as JSON")
	return cmd
}

// unixKeepStateUsage is the uninstall --keep-state help. It names the paths
// of the sandbox state a plain uninstall keeps, as the uninstall summary
// does (GAP-0067).
func unixKeepStateUsage(platform string) string {
	goos := "linux"
	if platform == "macos" {
		goos = "darwin"
	}
	kept := "the gateway's sandbox registrations, their key and the lifecycle's sandbox setup record"
	if layout, err := managed.StandaloneLayoutFor(goos); err == nil {
		store, key, record := layout.KeptSandboxStatePaths()
		kept = "the gateway's sandbox registrations (" + store + "), their key (" + key + ") and the lifecycle's sandbox setup record (" + record + ")"
	}
	return "keep the config, secrets, gateway and guardian state, logs and the service account, so a reinstall resumes with them (the deployment record goes either way); without it uninstall removes that state except " +
		kept + " while an account keeps sandboxes; --purge removes those too"
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

// lifecycleArgumentError reports an argument error of a lifecycle verb (an
// unknown flag, a malformed value, a stray argument, a --lock-wait out of
// range) with its invalid-arguments exit code. With --json, also when the
// parse stopped before it, stdout gets one lifecycle result whose only error
// is invalid_arguments, so an agent never classifies the failure by the exit
// code alone (GAP-2448). Linux and macOS keep the usage line on stderr for
// the MDM kit log; Windows prints the document only, as its other lifecycle
// failures do.
func lifecycleArgumentError(cmd *cobra.Command, action string, asJSON bool, err error) error {
	if err == nil || (!asJSON && !secretArgsRequestJSON(secretRawArgs())) {
		return err
	}
	message := err.Error()
	var usage *delegatedUsageError
	if errors.As(err, &usage) && usage.err != nil {
		message = usage.err.Error()
	}
	profile := managed.ProfileStandalone
	if secureClientHost() {
		profile = managed.ProfileSecureClient
	}
	result := enterprisestatus.New(action, profile, runtime.GOOS, "")
	result.AddError("invalid_arguments", message)
	result.Finish(runtime.GOOS, commandExitCode(err))
	data, mErr := json.MarshalIndent(result, "", "  ")
	if mErr != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	silenceJSONReportedError(cmd, runtime.GOOS == "windows", err)
	return err
}

func newEnterpriseSecretCommand(action, summary string) *cobra.Command {
	opts := &enterpriseSecretOptions{}
	cmd := &cobra.Command{
		Use:          action,
		Short:        summary,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseSecret(cmd, action, opts)
		},
	}
	if action != "status" {
		cmd.Flags().StringVar(&opts.name, "name", "", "credential name (1-63 lowercase letters, digits or dashes; starts with a letter or digit)")
		cmd.Flags().Lookup("name").Annotations = map[string][]string{
			secureClientUsageAnnotation: {"credential name (lowercase letters, digits and dashes)"},
		}
		_ = cmd.MarkFlagRequired("name")
	}
	if action == "set" {
		cmd.Flags().BoolVar(&opts.fromStdin, "from-stdin", false, "read the value from standard input")
		cmd.Flags().StringVar(&opts.fromFile, "from-file", "", "read the value from this file")
		cmd.Flags().StringVar(&opts.bundle, "bundle", "", "signed policy bundle (.dcbundle) that binds the new value; needed to change a credential the confirmed bundle binds")
		cmd.Flags().StringVar(&opts.ifConfirmed, "if-confirmed", "", "with --bundle: store the value only while the confirmed policy bundle has this manifest SHA-256 (none: no bundle is confirmed); else confirmed_bundle_changed and nothing is written")
	}
	if action == "set" || action == "remove" {
		cmd.Flags().StringVar(&opts.undoRotation, "undo-rotation", "", "put back a credential a failed rotation changed, only while the confirmed policy bundle has this manifest SHA-256 (none: no bundle is confirmed) and does not sign the value stored now; else rotation_confirmed and nothing changes")
		usage := "change only when the stored credential still has this exact SHA-256; required with --undo-rotation"
		if runtime.GOOS == "windows" {
			usage = "change only when the stored credential still has this exact SHA-256, or none for proven absence; required with --undo-rotation"
		}
		cmd.Flags().StringVar(&opts.ifStored, "if-stored", "", usage)
	}
	if action == "remove" {
		cmd.Flags().StringVar(&opts.undoConfig, "undo-config", "", "with --undo-rotation: the SHA-256 of the installed config before the rotation (none: no config); only while that config is still installed does remove take a credential it references, else credential_in_use and nothing is removed")
	}
	if action != "status" {
		addLockWaitFlag(cmd.Flags(), &opts.lockWait)
		if runtime.GOOS == "windows" {
			cmd.Flags().Lookup("lock-wait").Usage = windowsSecretLockWaitUsage
		}
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "print JSON")
	// An unknown flag, a malformed value, a stray argument or a missing
	// --name is invalid arguments: exit 2 (Windows 1639) with the usage line
	// and the --help pointer, as on enterprise linux|macos (GAP-2095).
	// Windows set, remove and status also print their --json failure
	// document.
	flagError := func(c *cobra.Command, err error) error {
		err = lifecycleFlagError(c, err)
		if enterpriseSecretArgumentRefusal != nil {
			return enterpriseSecretArgumentRefusal(c, action, opts, err)
		}
		return err
	}
	cmd.SetFlagErrorFunc(flagError)
	cmd.Args = func(c *cobra.Command, args []string) error {
		if err := strayArgumentError(c, args); err != nil {
			return flagError(c, err)
		}
		return nil
	}
	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		if err := cmd.ValidateRequiredFlags(); err != nil {
			return flagError(cmd, err)
		}
		return nil
	}
	return cmd
}

// windowsSecretLockWaitUsage is --lock-wait of Windows `secret set|remove`.
const windowsSecretLockWaitUsage = "wait up to this long for a policy bundle run to release bundle.lock (default: no wait, at most 15m) before exiting 1618; the installer's lifecycle.lock is waited for up to 30s either way"

// enterpriseSecretArgumentRefusal reports an argument error of `enterprise
// secret` the way the platform documents it: Windows prints the --json
// failure document (enterprise_secret_windows.go); nil elsewhere.
var enterpriseSecretArgumentRefusal func(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, err error) error

func init() {
	enterpriseSecretCmd.AddCommand(
		newEnterpriseSecretCommand("set", "Store a protected credential and apply it"),
		newEnterpriseSecretCommand("status", "List protected credentials without revealing values"),
		newEnterpriseSecretCommand("remove", "Remove a protected credential and apply the change"),
	)
	if check := newEnterpriseSecretCheckCommand(); check != nil {
		enterpriseSecretCmd.AddCommand(check)
	}
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
