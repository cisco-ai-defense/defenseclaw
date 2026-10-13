// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Seams for tests: the device bundle store and the effective policy the
// running gateway reports (nil when it could not be checked).
var (
	bundleStore         = func() (*enterprisebundle.Store, error) { return enterprisebundle.StoreFor(runtime.GOOS) }
	bundleGatewayPolicy = lifecycleGatewayPolicy
)

type bundleStatusResult struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	OK            bool   `json:"ok"`
	// BundleMode is true when the MDM installed the trust anchors.
	BundleMode  bool                          `json:"bundle_mode"`
	Anchors     string                        `json:"anchors,omitempty"`
	Current     *enterprisebundle.Ref         `json:"current"`
	LastGood    *enterprisebundle.Ref         `json:"last_good"`
	Floor       uint64                        `json:"floor"`
	LastReceipt *enterprisebundle.Receipt     `json:"last_receipt"`
	Bundle      *enterprisestatus.BundleState `json:"bundle,omitempty"`
	// GatewayChecked says whether the running gateway was asked; then
	// GatewayDigest is the digest it enforces and Applied says it is the
	// current bundle digest with no rejected reload.
	GatewayChecked bool                       `json:"gateway_checked"`
	GatewayDigest  string                     `json:"gateway_digest,omitempty"`
	Applied        bool                       `json:"applied"`
	Warnings       []enterprisebundle.Warning `json:"warnings"`
	Errors         []bundleError              `json:"errors"`
}

func newEnterpriseBundleStatusCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the bundle that enforces, the last receipt and the version floor",
		Long: `Report the policy bundle state of this standalone managed device: the
current (confirmed) bundle that enforces, the last good bundle kept for
rollback, the version floor, the last bundle receipt (state, error code and
times) and whether the running gateway enforces the current bundle digest.
It changes nothing. Run it as root or an administrator.`,
		Args:         bundleNoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			res := &bundleStatusResult{SchemaVersion: bundleOutputSchemaVersion, Command: "status",
				Warnings: []enterprisebundle.Warning{}, Errors: []bundleError{}}
			err := bundleStatus(bundleContext(cmd), res)
			if err != nil {
				res.Errors, err = bundleRefusal(err)
			}
			res.OK = err == nil
			return printBundleResult(cmd, asJSON, res, err, func(w io.Writer) { printStatusText(w, res) })
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON")
	cmd.SetFlagErrorFunc(lifecycleFlagError)
	return cmd
}

func bundleStatus(ctx context.Context, res *bundleStatusResult) error {
	if bundleSecureClient() {
		return secureClientBundleRefusal()
	}
	if !bundleManagedDevice() {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeNotManaged,
			Detail: "this computer is not a standalone managed device; bundle status reports a device"}
	}
	if path, err := bundleDefaultAnchors(); err == nil {
		res.Anchors = path
		_, statErr := os.Lstat(path)
		res.BundleMode = statErr == nil
	}
	store, err := bundleStore()
	if err != nil {
		return err
	}
	st, err := store.LoadState()
	if err != nil {
		return bundleStateError(err)
	}
	res.Current, res.LastGood, res.Floor = st.Current, st.LastGood, st.Floor
	receipts, err := store.Receipts()
	if err != nil {
		return bundleStateError(err)
	}
	if len(receipts) > 0 {
		res.LastReceipt = receipts[0]
		res.Bundle = receipts[0].Status(st.Current)
		switch last := receipts[0]; {
		case last.State == enterprisebundle.StateFailed:
			res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "bundle_failed",
				Message: fmt.Sprintf("the last bundle received failed (%s); the current bundle keeps enforcing", last.ErrorCode)})
		case !enterprisebundle.Finished(last.State):
			res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "bundle_pending",
				Message: "the last bundle received is " + last.State + " and not confirmed yet; the next lifecycle run settles it"})
		}
	} else if summary, err := store.Summary(); err == nil {
		res.Bundle = summary
	}
	if !res.BundleMode {
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "anchor_missing",
			Message: "no trust anchor file is installed, so this device does not take bundles"})
	}
	policy := bundleGatewayPolicy(ctx)
	if policy == nil {
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "gateway_unchecked",
			Message: "the running gateway policy could not be checked; run the enterprise status command of this platform"})
		return nil
	}
	res.GatewayChecked, res.GatewayDigest = true, policy.GatewayReportedDigest
	res.Applied = st.Current != nil && policy.GatewayReportedDigest != "" &&
		policy.GatewayReportedDigest == st.Current.EffectivePolicyDigest && policy.LastReloadError == ""
	if policy.LastReloadError != "" {
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "policy_reload_rejected",
			Message: "the gateway rejected its last reload and keeps enforcing the policy it last built"})
	}
	return nil
}

// bundleStateError is the refusal for a store that cannot be read: a
// standard account (not_root), else state_invalid.
func bundleStateError(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return &enterprisebundle.Error{Code: "not_root", Detail: "run this command as root or an administrator: the bundle state is readable only there"}
	}
	return &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
}

func printStatusText(w io.Writer, res *bundleStatusResult) {
	for _, warning := range res.Warnings {
		fmt.Fprintf(w, "warning: %s: %s\n", warning.Code, warning.Message)
	}
	if !res.OK {
		return
	}
	mode := "off"
	if res.BundleMode {
		mode = "on"
	}
	fmt.Fprintf(w, "Bundle mode: %s\n", mode)
	describe := func(label string, ref *enterprisebundle.Ref) {
		if ref == nil {
			fmt.Fprintf(w, "%s: none\n", label)
			return
		}
		fmt.Fprintf(w, "%s: %s version %d, effective digest %s, confirmed %s\n", label, ref.BundleID, ref.Version,
			enterprisestatus.ShortDigest(ref.EffectivePolicyDigest), ref.ConfirmedAt)
	}
	describe("Current", res.Current)
	describe("Last good", res.LastGood)
	fmt.Fprintf(w, "Version floor: %d\n", res.Floor)
	if r := res.LastReceipt; r != nil {
		line := fmt.Sprintf("Last receipt: %s version %d: %s", r.BundleID, r.Version, r.State)
		if r.ErrorCode != "" {
			line += " (" + string(r.ErrorCode) + ")"
		}
		if n := len(r.Transitions); n > 0 {
			line += " at " + r.Transitions[n-1].At
		}
		fmt.Fprintln(w, line)
	}
	if res.GatewayChecked {
		applied := "no"
		if res.Applied {
			applied = "yes"
		}
		fmt.Fprintf(w, "Gateway enforces %s; current bundle applied: %s\n", enterprisestatus.ShortDigest(res.GatewayDigest), applied)
	}
}
