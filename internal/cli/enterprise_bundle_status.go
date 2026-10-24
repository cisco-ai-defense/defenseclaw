// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	BundleMode bool   `json:"bundle_mode"`
	Anchors    string `json:"anchors,omitempty"`
	// AnchorsSummary describes the installed trust anchors; absent when
	// they are missing or fail their checks (see the warnings).
	AnchorsSummary          *enterprisebundle.AnchorsSummary      `json:"anchors_summary,omitempty"`
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
Status warns gateway_unchecked when the running gateway cannot be asked. The
receipt history keeps the last 20 receipts.
Run it as root or an administrator.`,
		Args:         bundleNoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			res := &bundleStatusResult{SchemaVersion: bundleOutputSchemaVersion, Command: "status",
				Warnings: []enterprisebundle.Warning{}, Errors: []bundleError{},
				// Replaced by the live scan; a status refused before it reports
				// the scan as unknown rather than the zero value.
				SessionsRestartRequired: enterprisestatus.SessionRestartStatus{State: "unknown", Entries: []enterprisestatus.SessionEntry{},
					Reason: "not scanned: bundle status was refused before the session scan"}}
			err := bundleStatus(bundleContext(cmd), res)
			if err != nil {
				res.Errors, err = bundleRefusal(err)
			}
			res.OK = err == nil
			if code := enterprisebundle.CodeOf(err); code == enterprisebundle.CodeNotAdmin || code == enterprisebundle.CodeNotRoot {
				// The protected state was not read. Do not present zero values as
				// facts about the device in the privilege refusal (GAP-1052).
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
	var anchors *enterprisebundle.Anchors
	var anchorsErr error
	if path, err := bundleDefaultAnchors(); err == nil {
		res.Anchors = path
		_, statErr := os.Lstat(path)
		res.BundleMode = statErr == nil
		var raw []byte
		anchors, raw, anchorsErr = enterprisebundle.ReadAnchorsFile(path, bundleAnchorTrust)
		res.AnchorsSummary = enterprisebundle.SummarizeAnchors(anchors, raw)
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
			message := "the last bundle received failed (" + string(last.ErrorCode) + "); the device remains on its base policy"
			if st.Current != nil {
				message = "the last bundle received failed (" + string(last.ErrorCode) + "); the current bundle keeps enforcing"
			}
			res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "bundle_failed",
				Message: message})
		case !enterprisebundle.Finished(last.State):
			res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: enterprisebundle.WarnBundlePending,
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
		// The signed manifest in the immutable current version tells status
		// whether the running build can compare the expected and live
		// digests: an upgrade since the apply makes the signed digest
		// unverifiable.
		if raw, err := os.ReadFile(filepath.Join(store.VersionDir(st.Current.Dir), enterprisebundle.ManifestName)); err == nil {
			if manifest, err := enterprisebundle.DecodeManifest(raw); err == nil {
				manifestKnown = true
				signedExpected = manifest.EffectivePolicy.Digests[runtime.GOOS]
				digestComparable = enterprisebundle.DigestComparable(manifest, appVersion)
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
	// On a device whose managed layout changed its digest, verify proved
	// the signed digest against the standard layout and the gateway enforces
	// this device's own digest, so the signed one never matches it there.
	gatewayComparable := digestComparable && (currentReceipt == nil || !slices.Contains(currentReceipt.WarningCodes, enterprisebundle.WarnDigestLayoutUnverifiable))
	addReceiptWarning := func(code string) {
		if code == "" {
			return
		}
		for _, existing := range res.Warnings {
			if existing.Code == code {
				return
			}
		}
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: code, Message: bundleReceiptWarningMessage(code, currentReceipt)})
	}
	// The state records the signer of the current bundle, so the check
	// still runs once its confirmed receipt was pruned.
	signer := ""
	if currentReceipt != nil {
		signer = currentReceipt.SignerKeyID
	} else if st.Current != nil {
		signer = st.Current.SignerKeyID
	}
	if warning := bundleAnchorsSignerWarning(res.Anchors, anchors, anchorsErr, signer); warning != nil {
		res.Warnings = append(res.Warnings, *warning)
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
	} else if warning := bundleAnchorsFileWarning(anchorsErr); warning != nil {
		res.Warnings = append(res.Warnings, *warning)
	}
	policy := bundleGatewayPolicy(ctx)
	if policy == nil {
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "gateway_unchecked",
			Message: "the running gateway policy could not be checked; run the enterprise status command of this platform"})
		return nil
	}
	res.GatewayChecked, res.GatewayDigest = true, policy.GatewayReportedDigest
	if st.Current != nil {
		addReceiptWarning(enterprisebundle.DigestWarningCode(signedExpected, policy.GatewayReportedDigest, gatewayComparable))
	}
	res.Applied = st.Current != nil && policy.Applied && !policy.ConfigUnrecorded && policy.GatewayReportedDigest != "" &&
		policy.EffectiveDigest == policy.GatewayReportedDigest &&
		policy.GatewayReportedDigest == st.Current.EffectivePolicyDigest && policy.LastReloadError == ""
	if st.Current != nil && !res.Applied && policy.Applied && !policy.ConfigUnrecorded && policy.LastReloadError == "" &&
		policy.EffectiveDigest != "" && policy.EffectiveDigest == policy.GatewayReportedDigest {
		// A confirmed receipt keeps the digest of the build that applied it.
		// An upgrade can change the derived digest without changing the
		// signed bundle. The state pins the manifest that was verified on
		// apply; read it and its hashed files again with this build, then
		// check its exact rendered config against the installed bytes. Anchor
		// rotation after confirmation does not change what now enforces.
		if digest, rendered, err := currentBuildBundleDigest(ctx, store, st.Current); err == nil && digest == policy.EffectiveDigest {
			if installed, err := bundleInstalledConfig(runtime.GOOS); err == nil && bytes.Equal(installed, rendered) {
				res.Applied = true
				current := *st.Current
				current.EffectivePolicyDigest = digest
				res.Current = &current
				if res.Bundle != nil && res.Bundle.BundleID == current.BundleID && res.Bundle.Version == current.Version &&
					res.Bundle.State == enterprisebundle.StateConfirmed {
					res.Bundle.EffectivePolicyDigest = digest
				}
			}
		}
	}
	if policy.LastReloadError != "" {
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "policy_reload_rejected",
			Message: "the gateway rejected its last reload and keeps enforcing the policy it last built"})
	}
	return nil
}

func currentBuildBundleDigest(ctx context.Context, store *enterprisebundle.Store, ref *enterprisebundle.Ref) (string, []byte, error) {
	layout, err := enterprisebundle.Layout(runtime.GOOS)
	if err != nil {
		return "", nil, err
	}
	return enterprisebundle.VerifiedCurrentDigest(ctx, store, ref, runtime.GOOS,
		enterprisebundle.DeviceLayoutFromManaged(layout), bundleDigester)
}

// bundleReceiptWarningMessage explains a warning code the confirmed
// receipt recorded, in the lifecycle result's words where it has them
// (receipt_publish_failed read as a digest mismatch, GAP-1013). Digest
// mismatch codes keep the generic text.
func bundleReceiptWarningMessage(code string, receipt *enterprisebundle.Receipt) string {
	if message, ok := enterprisestatus.BundleReceiptWarningMessage(code); ok {
		return message
	}
	switch code {
	case enterprisebundle.WarnConfirmedAfterInterrupt:
		return "the run that applied this bundle ended before the gateway confirmed it; a later lifecycle run confirmed it once the gateway reported its policy"
	case "capability_disabled":
		if receipt == nil {
			return "the bundle disabled a capability"
		}
		return "the bundle disabled: " + strings.Join(receipt.DisabledByBundle, ", ")
	case "sessions_scan_unknown":
		// Windows records a session scan that did not finish when the
		// bundle applied (GAP-0104); it says nothing about the digest.
		return "running agent sessions could not be checked when this bundle applied; restart any agent session opened before it"
	}
	return "the gateway's effective policy digest differs from the signed expected digest"
}

func bundleCurrentSignerWarning(anchorsPath, signerKeyID string) *enterprisebundle.Warning {
	if anchorsPath == "" || signerKeyID == "" {
		return nil
	}
	anchors, err := enterprisebundle.LoadAnchors(anchorsPath, bundleAnchorTrust)
	return bundleAnchorsSignerWarning(anchorsPath, anchors, err, signerKeyID)
}

// bundleAnchorsSignerWarning is bundleCurrentSignerWarning for anchors the
// caller already read from anchorsPath (loadErr: the read failed).
func bundleAnchorsSignerWarning(anchorsPath string, anchors *enterprisebundle.Anchors, loadErr error, signerKeyID string) *enterprisebundle.Warning {
	if anchorsPath == "" || signerKeyID == "" {
		return nil
	}
	if loadErr != nil {
		return &enterprisebundle.Warning{Code: "anchor_unreadable", Message: "the installed trust anchors could not be checked for the confirmed bundle signer"}
	}
	return bundleSignerWarning(anchors, signerKeyID)
}

// bundleAnchorsFileWarning explains an installed anchor file that fails its
// checks (anchor_insecure, anchor_invalid), with or without a confirmed
// bundle: anchors_summary is then absent and every bundle is refused until
// the file is fixed. nil when the read succeeded.
func bundleAnchorsFileWarning(loadErr error) *enterprisebundle.Warning {
	if loadErr == nil {
		return nil
	}
	code := enterprisebundle.CodeOf(loadErr)
	if code != enterprisebundle.CodeAnchorInsecure {
		code = enterprisebundle.CodeAnchorInvalid
	}
	return &enterprisebundle.Warning{Code: string(code),
		Message: "the installed trust anchor file fails its checks, so this device refuses every bundle until the file is fixed: " + loadErr.Error()}
}

// bundleSignerWarning is key_unknown or key_revoked when anchors no longer
// trust the confirmed bundle signer ("" for none); nil otherwise.
func bundleSignerWarning(anchors *enterprisebundle.Anchors, signerKeyID string) *enterprisebundle.Warning {
	if anchors == nil || signerKeyID == "" {
		return nil
	}
	key := anchors.Key(signerKeyID)
	if key == nil {
		return &enterprisebundle.Warning{Code: string(enterprisebundle.CodeKeyUnknown), Message: fmt.Sprintf("the confirmed bundle signer %s is absent from the installed trust anchors", signerKeyID)}
	}
	if key.Status == enterprisebundle.KeyRevoked {
		return &enterprisebundle.Warning{Code: string(enterprisebundle.CodeKeyRevoked), Message: fmt.Sprintf("the confirmed bundle signer %s is revoked in the installed trust anchors; review the device policy", signerKeyID)}
	}
	return nil
}

// bundleStateError is the refusal for a store that cannot be read: a
// standard account (not_root), else state_invalid.
func bundleStateError(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeNotRoot, Detail: "run this command as root or an administrator: the bundle state is readable only there"}
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
	if a := res.AnchorsSummary; a != nil {
		fmt.Fprintf(w, "Trust anchors: tenant %s, %d keys, minimum version %d, sha256 %s\n", a.TenantID, len(a.Keys), a.MinVersion, a.SHA256[:12])
	}
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
		if r.RollbackOf != "" {
			fmt.Fprintf(w, "Rollback of: %s\n", r.RollbackOf)
		}
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
