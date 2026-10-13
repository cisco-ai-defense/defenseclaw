// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"time"

	"github.com/spf13/cobra"
)

type bundleApplyOptions struct {
	bundle, reason string
	inbox, json    bool
	lockWait       time.Duration
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
apply of the current bundle is a no-op (already_applied). --inbox applies the
highest version in <etc>/bundles/inbox and removes the processed files.
Exit codes: 0, 1 (errors[].code names the refusal), 75 busy, 2 usage.`,
		Args:         bundleNoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseBundleApply(cmd, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.bundle, "bundle", "", "the .dcbundle file or bundle directory")
	f.BoolVar(&opts.inbox, "inbox", false, "apply the highest version in the bundle inbox")
	f.StringVar(&opts.reason, "reason", "bundle", "annotate the run (recorded in the lifecycle result)")
	addLockWaitFlag(f, &opts.lockWait)
	f.BoolVar(&opts.json, "json", false, "print the result as JSON")
	cmd.SetFlagErrorFunc(lifecycleFlagError)
	return cmd
}

// bundleApplyRefused prints an apply refused before the lifecycle ran.
func bundleApplyRefused(cmd *cobra.Command, asJSON bool, err error) error {
	res := &bundleApplyResult{SchemaVersion: bundleOutputSchemaVersion, Command: "apply", Errors: []bundleError{}}
	res.Errors, err = bundleRefusal(err)
	return printBundleResult(cmd, asJSON, res, err, func(io.Writer) {})
}
