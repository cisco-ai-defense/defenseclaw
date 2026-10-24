// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

type bundleApplyOptions struct {
	bundle, reason       string
	deliveryID           string
	inbox, json          bool
	refuseCapabilityLoss bool
	deferRestart         bool
	lockWait             time.Duration
}

// bundleApplyResult is the document of an apply refused before the
// lifecycle ran (a Secure Client computer, not a managed device); every other
// apply prints the lifecycle result v2 with its bundle block.
type bundleApplyResult struct {
	SchemaVersion int           `json:"schema_version"`
	Command       string        `json:"command"`
	OK            bool          `json:"ok"`
	Errors        []bundleError `json:"errors"`
}

func newEnterpriseBundleApplyCommand() *cobra.Command {
	opts := &bundleApplyOptions{}
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a signed policy bundle (root, standalone enterprise)",
		Long: `Apply a signed policy bundle on this standalone managed device. The bundle
is copied into the bundle store and verified there (the checks of bundle
verify, the version floor and the credentials included), then installed by the
ensure transaction. The policy in force keeps enforcing until the gateway
reports the new policy; a failed or interrupted apply keeps or puts back the
last good bundle. Every apply ends in a receipt (bundle status). A repeated
apply of the current bundle is a no-op (already_applied). On Linux and macOS,
--inbox applies the highest version in <etc>/bundles/inbox and removes the
files it processed; every lower version it processed gets a receipt that ends
failed with superseded. One run processes at most 16 inbox files, in file-name
order; the rest stay for the next run. Windows has no inbox: give --bundle.
If the current-version directory is damaged, ensure and repair on Linux and
macOS keep the installed config, warn bundle_state_unreadable and still repair
the host. On Windows they stop with bundle_restore_failed and repair nothing.
Either way, deliver a new signed bundle to replace it.
--defer-restart refuses a bundle whose config change restarts the gateway
before anything changes (restart_deferred, exit 75, Windows 1618): the
restart_prediction of bundle verify. --delivery-id records an opaque caller id (1 to 128 of A-Z a-z 0-9 . _ : -)
on the receipt, receipt.json and the result bundle block.
Exit codes: 0, 1 (errors[].code names the refusal), 75 busy, 2 usage. With
--json, an argument error prints one refusal document (invalid_arguments).`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := bundleNoArgs(cmd, args); err != nil {
				return bundleApplyArgumentError(cmd, opts, err)
			}
			return nil
		},
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := &countingWriter{w: cmd.OutOrStdout()}
			cmd.SetOut(out)
			err := runEnterpriseBundleApply(cmd, opts)
			if out.n == 0 && err != nil && commandExitCode(err) == enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
				return bundleApplyArgumentError(cmd, opts, err)
			}
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.bundle, "bundle", "", "the .dcbundle file or bundle directory")
	f.BoolVar(&opts.inbox, "inbox", false, "apply the highest version in the bundle inbox (Linux and macOS)")
	f.BoolVar(&opts.refuseCapabilityLoss, "refuse-capability-loss", false, "refuse a bundle that disables a currently enforced capability")
	f.BoolVar(&opts.deferRestart, "defer-restart", false, "refuse, before anything changes, a bundle whose config change restarts the gateway (restart_deferred, retry exit code)")
	f.StringVar(&opts.reason, "reason", "bundle", "annotate the run (recorded in the lifecycle result)")
	f.StringVar(&opts.deliveryID, "delivery-id", "", "opaque id of this delivery, recorded on its receipt (1 to 128 of A-Z a-z 0-9 . _ : -)")
	addLockWaitFlag(f, &opts.lockWait)
	if runtime.GOOS == "windows" {
		f.Lookup("lock-wait").Usage = windowsApplyLockWaitUsage
		f.Lookup("reason").Usage = "accepted for one command line on every OS; has no effect on Windows"
	}
	f.BoolVar(&opts.json, "json", false, "print the result as JSON")
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return bundleApplyArgumentError(c, opts, lifecycleFlagError(c, err))
	})
	return cmd
}

// bundleApplyArgumentError reports an argument error of bundle apply (an
// unknown flag, a malformed value, a stray argument, a missing or doubled
// source, a --lock-wait or --delivery-id out of range): the usage line and
// the invalid-arguments exit code, and with --json (also when the parse
// stopped before it) one refusal document with invalid_arguments, so an
// agent never classifies the failure by the exit code alone.
func bundleApplyArgumentError(cmd *cobra.Command, opts *bundleApplyOptions, err error) error {
	if !opts.json && !secretArgsRequestJSON(secretRawArgs()) {
		return err
	}
	message := err.Error()
	var usage *delegatedUsageError
	if errors.As(err, &usage) && usage.err != nil {
		message = usage.err.Error()
	}
	res := &bundleApplyResult{SchemaVersion: bundleOutputSchemaVersion, Command: "apply",
		Errors: []bundleError{{Code: "invalid_arguments", Message: message}}}
	data, mErr := json.MarshalIndent(res, "", "  ")
	if mErr != nil {
		return mErr
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	// Windows prints the document only, as its other lifecycle verbs do;
	// Linux and macOS keep the usage line on stderr for the MDM kit log.
	silenceJSONReportedError(cmd, runtime.GOOS == "windows", err)
	return err
}

// countingWriter counts what a command wrote to its stdout.
type countingWriter struct {
	w io.Writer
	n int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += n
	return n, err
}

// windowsApplyLockWaitUsage is --lock-wait of Windows `bundle apply`: it
// covers bundle.lock only, and its default is no wait.
const windowsApplyLockWaitUsage = "wait up to this long for another policy bundle run to release bundle.lock (default: no wait, at most 15m) before exiting 1618"

// checkDeliveryID refuses a --delivery-id that was given (also as "") but is
// not 1 to 128 of A-Z a-z 0-9 . _ : -, with the invalid-arguments exit code
// (2, Windows 1639), as every other apply argument error.
func checkDeliveryID(cmd *cobra.Command, id string) error {
	if id == "" && !cmd.Flags().Changed("delivery-id") {
		return nil
	}
	if err := enterprisestatus.CheckDeliveryID(id); err != nil {
		return lifecycleFlagError(cmd, err)
	}
	return nil
}

// bundleApplyRefused prints an apply refused before the lifecycle ran.
func bundleApplyRefused(cmd *cobra.Command, asJSON bool, err error) error {
	res := &bundleApplyResult{SchemaVersion: bundleOutputSchemaVersion, Command: "apply", Errors: []bundleError{}}
	res.Errors, err = bundleRefusal(err)
	return printBundleResult(cmd, asJSON, res, err, func(io.Writer) {})
}
