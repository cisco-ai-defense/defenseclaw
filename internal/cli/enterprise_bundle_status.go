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
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Seams for tests: the device bundle store and the effective policy the
// running gateway reports (nil when it could not be checked).
var (
	bundleStore         = func() (*enterprisebundle.Store, error) { return enterprisebundle.StoreFor(runtime.GOOS) }
	bundleGatewayPolicy = lifecycleGatewayPolicy
	bundleSessionStatus = platformBundleSessionStatus
	// Windows uses this to finish a receipt left applied by a killed CLI.
	bundleSettleStatus = func(context.Context) error { return nil }
)

type bundleStatusResult struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	OK            bool   `json:"ok"`
	// BundleMode is true when the MDM installed the trust anchors.
	BundleMode              bool                                  `json:"bundle_mode"`
	Anchors                 string                                `json:"anchors,omitempty"`
	Current                 *enterprisebundle.Ref                 `json:"current"`
	LastGood                *enterprisebundle.Ref                 `json:"last_good"`
	Floor                   uint64                                `json:"floor"`
	LastReceipt             *enterprisebundle.Receipt             `json:"last_receipt"`
	LastRefusal             *enterprisestatus.BundleRefusal       `json:"last_refusal,omitempty"`
	Bundle                  *enterprisestatus.BundleState         `json:"bundle,omitempty"`
	SessionsRestartRequired enterprisestatus.SessionRestartStatus `json:"sessions_restart_required"`
	AlertOnlyRuleCount      int                                   `json:"alert_only_rule_count"`
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
		Short: "Show the confirmed bundle, running digest, last receipt and version floor",
		Long: `Report the policy bundle state of this standalone managed device: the
current (confirmed) bundle, the last good bundle kept for
rollback, the version floor, the last enforcing receipt, the last refusal
and whether the running gateway enforces the current bundle digest.
On Windows, status confirms an applied receipt left by an interrupted run
only after the installed config and running gateway pass the confirm gate.
Run it as root or an administrator.`,
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
			if enterprisebundle.CodeOf(err) == enterprisebundle.CodeNotAdmin {
				// The protected state was not read. Do not present zero values as
				// facts about the device in the privilege refusal.
				return printBundleResult(cmd, asJSON, struct {
					SchemaVersion int           `json:"schema_version"`
					Command       string        `json:"command"`
					OK            bool          `json:"ok"`
					Errors        []bundleError `json:"errors"`
				}{bundleOutputSchemaVersion, "status", false, res.Errors}, err, func(io.Writer) {})
			}
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
	if err := bundlePrivilege(); err != nil {
		return err
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
	if err := bundleSettleStatus(ctx); err != nil {
		return bundleStateError(err)
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
	res.LastReceipt, res.LastRefusal, err = store.Latest()
	if err != nil {
		return bundleStateError(err)
	}
	if res.LastReceipt != nil {
		res.Bundle = res.LastReceipt.Status(st.Current)
		switch last := res.LastReceipt; {
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
	res.SessionsRestartRequired = bundleSessionStatus(ctx)
	if res.Bundle != nil {
		res.Bundle.SessionsRestartRequired = &res.SessionsRestartRequired
	}
	if code, message := enterprisestatus.SessionWarning(res.SessionsRestartRequired); code != "" {
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: code, Message: message})
	}
	var currentReceipt *enterprisebundle.Receipt
	var signedExpected string
	var digestComparable bool
	var manifestKnown bool
	if st.Current != nil {
		if bundle, err := store.ReadVersion(st.Current); err == nil {
			if cfg, _, err := enterprisebundle.LoadConfig(bundle, store.VersionDir(st.Current.Dir)); err == nil {
				if warnings, count, err := enterprisebundle.RuleNotBlockingWarnings(cfg); err == nil {
					res.AlertOnlyRuleCount = count
					res.Warnings = append(res.Warnings, warnings...)
				}
			}
		}
		for _, rc := range receipts {
			if rc.State == enterprisebundle.StateConfirmed && rc.BundleID == st.Current.BundleID && rc.Version == st.Current.Version {
				currentReceipt = rc
				break
			}
		}
		// Older receipts predate digest_comparable. The signed manifest in
		// the immutable current version still tells status whether this
		// platform and build can compare the expected and live digests.
		if raw, err := os.ReadFile(filepath.Join(store.VersionDir(st.Current.Dir), enterprisebundle.ManifestName)); err == nil {
			if manifest, err := enterprisebundle.DecodeManifest(raw); err == nil {
				manifestKnown = true
				signedExpected = manifest.EffectivePolicy.Digests[runtime.GOOS]
				digestComparable = enterprisebundle.DigestComparable(manifest, appVersion, runtime.GOOS)
			}
		}
	}
	if currentReceipt != nil {
		if !manifestKnown && currentReceipt.ExpectedDigest != "" {
			signedExpected = currentReceipt.ExpectedDigest
		}
		if manifestKnown {
			currentReceipt.SetDigestUnverifiable(!digestComparable)
			if res.LastReceipt != nil && res.LastReceipt.ReceiptID == currentReceipt.ReceiptID {
				res.LastReceipt.SetDigestUnverifiable(!digestComparable)
				if res.Bundle != nil {
					res.Bundle.WarningCodes = append([]string(nil), res.LastReceipt.WarningCodes...)
				}
			}
		} else {
			digestComparable = currentReceipt.DigestComparable
		}
	}
	addReceiptWarning := func(code string) {
		if code == "" {
			return
		}
		for _, existing := range res.Warnings {
			if existing.Code == code {
				return
			}
		}
		message := "the gateway's effective policy digest differs from the signed expected digest"
		switch code {
		case enterprisebundle.WarnDigestUnverifiable:
			message = "the signed expected digest cannot be compared with the gateway's effective policy digest on this product version or platform"
		case enterprisebundle.WarnDigestLayoutUnverifiable:
			message = "the device's non-standard managed layout changed the effective digest; the gateway's enforcing digest was recorded"
		case "capability_disabled":
			message = "the bundle disabled: " + strings.Join(currentReceipt.DisabledByBundle, ", ")
		}
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: code, Message: message})
	}
	if currentReceipt != nil {
		for _, code := range currentReceipt.WarningCodes {
			addReceiptWarning(code)
		}
	} else if manifestKnown && !digestComparable {
		addReceiptWarning(enterprisebundle.WarnDigestUnverifiable)
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
	if st.Current != nil {
		addReceiptWarning(enterprisebundle.DigestWarningCode(signedExpected, policy.GatewayReportedDigest, digestComparable))
	}
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
	if r := res.LastRefusal; r != nil {
		fmt.Fprintf(w, "Last refusal: %s version %d: %s at %s\n", r.BundleID, r.Version, r.ErrorCode, r.Time)
	}
	fmt.Fprintf(w, "Running sessions needing restart: %d (%s)\n", res.SessionsRestartRequired.Count, res.SessionsRestartRequired.State)
	if res.SessionsRestartRequired.Reason != "" {
		fmt.Fprintf(w, "Session scan: %s\n", res.SessionsRestartRequired.Reason)
	}
	enterprisestatus.WriteSessionEntries(w, res.SessionsRestartRequired)
	fmt.Fprintf(w, "Detection-only custom rules: %d\n", res.AlertOnlyRuleCount)
	if res.GatewayChecked {
		applied := "no"
		if res.Applied {
			applied = "yes"
		}
		fmt.Fprintf(w, "Gateway enforces %s; current bundle applied: %s\n", enterprisestatus.ShortDigest(res.GatewayDigest), applied)
	}
}
