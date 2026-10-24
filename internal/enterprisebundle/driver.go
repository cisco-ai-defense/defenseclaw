// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// ErrConfirmationPrerequisiteMissing means an applied receipt cannot be
// confirmed until a later delivery repairs a missing local prerequisite.
// SettleRun keeps that receipt pending so the repairing delivery can proceed.
var ErrConfirmationPrerequisiteMissing = errors.New("bundle confirmation prerequisite missing")

// Driver applies a bundle around a lifecycle transaction it does not run
// itself: the Windows lifecycle, whose transaction is the installer module.
// Prepare receives the bundle (receipt), stages it, verifies the staged copy
// (never the path it was delivered at), promotes it to its immutable version
// directory and renders its config.yaml against that directory. The caller
// then installs that config with its own ensure transaction, which rolls
// back on its own failure. Finish confirms the bundle only once the running
// gateway reports the effective policy of the installed config with no
// reload error. A committed config whose gateway cannot answer stays
// applied and pending; a rejected candidate fails and the caller restores
// the last good config. Until confirmation, bundle-state.json still
// names the last good bundle, so a run that stops in between is settled by
// SettleRun at the start of the next one.
type Driver struct {
	Store       *Store
	AnchorsPath string
	// ConfigPath names the live config and its durable lifecycle generation.
	ConfigPath string
	// AnchorTrust is the device trust check of the anchor file.
	AnchorTrust    func(path string) error
	Platform       string
	ProductVersion string
	DeviceLayout   *DeviceLayout
	Now            func() time.Time
	// SecretValue reads a credential as the gateway would (VerifyInput).
	SecretValue func(name string) ([]byte, error)
	Digester    PolicyDigester
	// TrustVersion checks the promoted version directory before its config
	// is rendered (Windows: owned by SYSTEM or Administrators, no write
	// entry for another account); nil skips it.
	TrustVersion func(dir string) error
	// EnforcedConfig is the currently installed, enforcing config. A nil
	// value means this is the first bundle on a device with no config.
	EnforcedConfig       []byte
	RefuseCapabilityLoss bool
	// RefuseRestart, when set (apply --defer-restart), names why the change
	// from the enforced config to the rendered bundle config restarts the
	// gateway ("" when it does not); a reason refuses the bundle
	// (restart_deferred) before it is promoted.
	RefuseRestart func(enforced, rendered []byte) string
	// DeliveryID is the --delivery-id Prepare records on the receipt it
	// starts ("" for none).
	DeliveryID string
	// CurrentReceiptID is the receipt of the delivery this process installs
	// ("" when it installs none): ConfigGenerationOptions attributes bytes
	// that staged receipts of different bundles render to it.
	CurrentReceiptID string
}

// Prepared is a bundle ready for the ensure transaction.
type Prepared struct {
	Receipt  *Receipt
	Manifest *Manifest
	// FloorSource records the authority that set the verified version floor,
	// including when verification refused the proposed bundle.
	FloorSource string
	// Config is the rendered config.yaml the transaction installs and
	// ConfigSHA256 its hex SHA-256.
	Config       []byte
	ConfigSHA256 string
	// EffectivePolicyDigest is the policy verified from this build's staged
	// bundle. A committed config keeps this digest while its gateway is down
	// and the receipt waits in applied for a later live confirmation.
	EffectivePolicyDigest string
	// AlreadyApplied is a repeated delivery of the current bundle: its
	// receipt was discarded and Config is the current bundle config.
	AlreadyApplied bool
	Warnings       []Warning
	// InstalledPending is set when Finish failed this delivery while the
	// deployment holds the committed config of another receipt that no run
	// has confirmed or failed yet: that config is neither this bundle's nor
	// the last good one, nothing was rolled back, and the next run settles
	// that receipt.
	InstalledPending *Receipt
}

// GatewayPolicy is what the running gateway reports after the transaction.
type GatewayPolicy struct {
	// EffectiveDigest is computed from the installed config; Digest is what
	// the running gateway reports. They must agree before confirmation.
	EffectiveDigest string
	Digest          string
	Generation      uint64
	BundleID        string
	BundleVersion   uint64
	ReloadError     string
	// Applied is true when Digest is the effective policy digest of the
	// installed config.
	Applied bool
}

// Unavailable reports a gateway that could not be read at all (nil: the
// policy digest command gave no answer) or that answered without a policy
// digest and without a rejected reload (not running, not ready). Settling
// treats it as a temporary outage: it proves nothing, so a bundle whose
// apply was proven or committed stays pending until a run can read the
// gateway again, and is never failed for it.
func (p *GatewayPolicy) Unavailable() bool {
	return p == nil || (p.Digest == "" && p.ReloadError == "")
}

// NoBaseConfig is Receipt.BaseConfigSHA256 for a run that started with no
// installed config.
const NoBaseConfig = "none"

// ConfirmPolicyDigests applies the signed bundle's integrity contract on
// every platform. A cross-version or cross-platform signature is not
// comparable, but the installed config and gateway still have to agree.
func ConfirmPolicyDigests(expected, effective, gateway string, comparable bool) error {
	if digestPattern.MatchString(effective) && digestPattern.MatchString(gateway) && effective != gateway {
		return &Error{Code: CodeDigestMismatch, Detail: "the gateway digest differs from the installed bundle policy digest"}
	}
	if comparable && digestPattern.MatchString(effective) && effective != expected {
		return &Error{Code: CodeDigestMismatch, Detail: "the installed bundle policy digest differs from the signed expected digest"}
	}
	return nil
}

func (d *Driver) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Prepare runs every step before the transaction. b is the delivered bundle
// and readErr why it could not be read. On a refusal the receipt (when one
// could be written) is failed with the code and the error carries it.
func (d *Driver) Prepare(ctx context.Context, b *Bundle, readErr error) (*Prepared, error) {
	id, version := "", uint64(0)
	if readErr == nil && b != nil {
		if m, err := DecodeManifest(b.Manifest); err == nil {
			id, version = m.BundleID, m.Version
		}
	}
	receipt, err := d.Store.Receive(id, version, d.DeliveryID)
	if err != nil {
		return nil, &Error{Code: CodeStateInvalid, Detail: "cannot write the policy bundle receipt: " + err.Error()}
	}
	p := &Prepared{Receipt: receipt}
	refuse := func(err error) (*Prepared, error) {
		code := CodeOf(err)
		if code == "" {
			code = CodeApplyFailed
			err = &Error{Code: code, Detail: err.Error()}
		}
		_ = d.Store.Fail(receipt, code, err.Error())
		return p, err
	}
	if readErr != nil {
		return refuse(readErr)
	}
	staging, err := d.Store.Stage(receipt, b)
	if err != nil {
		return refuse(StageError(err))
	}
	staged, err := ReadDir(staging)
	if err != nil {
		return refuse(err)
	}
	if d.Digester == nil {
		return refuse(&Error{Code: CodeConfigInvalid, Detail: "this build cannot compute the effective policy digest of a bundle"})
	}
	anchors, err := LoadAnchors(d.AnchorsPath, d.AnchorTrust)
	if err != nil {
		return refuse(err)
	}
	st, err := d.Store.LoadState()
	if err != nil {
		return refuse(&Error{Code: CodeStateInvalid, Detail: err.Error()})
	}
	res, err := Verify(ctx, VerifyInput{
		Bundle: staged, Anchors: anchors, Platform: d.Platform, Now: d.now().UTC(), Confirmed: st.Confirmed(),
		ProductVersion: d.ProductVersion, DeviceLayout: d.DeviceLayout, SecretValue: d.SecretValue, RequireSecretPresence: true,
		Stage:    func(*Bundle) (string, error) { return staging, nil },
		Digester: d.Digester,
	})
	p.FloorSource = res.FloorSource
	p.Warnings = res.Warnings
	if err != nil {
		return refuse(err)
	}
	if err := d.Store.RefuseBelowPending(receipt, res.Manifest, sha256Hex(staged.Manifest)); err != nil {
		return refuse(err)
	}
	p.Manifest = res.Manifest
	p.EffectivePolicyDigest = res.EffectivePolicyDigest
	if res.AlreadyApplied {
		raw, _, err := d.CurrentConfig()
		if err != nil {
			_ = d.Store.Discard(receipt)
			return p, &Error{Code: CodeStateInvalid, Detail: "cannot read the current policy bundle: " + err.Error()}
		}
		// The repeat installs the current bundle config again over an
		// installed config that may have drifted: a restart that change
		// needs is deferred as for a new bundle, before any transaction.
		if d.RefuseRestart != nil {
			if reason := d.RefuseRestart(d.EnforcedConfig, raw); reason != "" {
				return refuse(&Error{Code: CodeRestartDeferred, Detail: reason})
			}
		}
		if err := d.Store.Discard(receipt); err != nil {
			p.Warnings = append(p.Warnings, Warning{Code: "bundle_state_unreadable",
				Message: "could not remove the receipt of the repeated delivery: " + err.Error()})
		}
		p.Receipt, p.AlreadyApplied, p.Config, p.ConfigSHA256 = nil, true, raw, sha256Hex(raw)
		return p, nil
	}
	// Verify computed the effective policy from the staged tree. Enforce the
	// comparable signed digest here, before promotion hands Config to the
	// caller's activation transaction. Finish still confirms the live digest.
	if err := ConfirmPolicyDigests(res.ExpectedDigest, res.EffectivePolicyDigest, res.EffectivePolicyDigest, res.DigestVerified); err != nil {
		return refuse(err)
	}
	m := res.Manifest
	if err := d.Store.Advance(receipt, StateVerified, func(rc *Receipt) {
		rc.TenantID, rc.DeviceGroup, rc.Principal = m.TenantID, m.Target.DeviceGroup, m.CreatedBy
		rc.ChangeSummary, rc.RollbackOf = m.ChangeSummary, m.RollbackOf
		rc.SignerKeyID, rc.ManifestSHA256, rc.ExpectedDigest = res.Signature.KeyID, sha256Hex(staged.Manifest), res.ExpectedDigest
		rc.SetDigestComparison(res.DigestVerified, res.DigestUnverifiable, res.DigestLayoutUnverifiable)
	}); err != nil {
		return refuse(err)
	}
	versionName := VersionDirNameForReceipt(receipt.Version, receipt.BundleID, receipt.ReceiptID)
	rendered, err := RenderConfig(staged, d.Store.VersionDir(versionName))
	if err != nil {
		return refuse(err)
	}
	p.Config, p.ConfigSHA256 = rendered, sha256Hex(rendered)
	if err := RefuseDeviceKeyMove(d.EnforcedConfig, rendered, d.Platform, d.DeviceLayout); err != nil {
		return refuse(err)
	}
	loss, err := DisabledByBundle(d.EnforcedConfig, rendered)
	if err != nil {
		return refuse(&Error{Code: CodeStateInvalid, Detail: err.Error()})
	}
	receipt.DisabledByBundle = loss
	if len(loss) > 0 {
		receipt.WarningCodes = append(receipt.WarningCodes, "capability_disabled")
		p.Warnings = append(p.Warnings, Warning{Code: "capability_disabled", Message: "the bundle disables: " + strings.Join(loss, ", ")})
		if d.RefuseCapabilityLoss {
			return refuse(&Error{Code: CodeCapabilityLoss, Detail: "the bundle disables: " + strings.Join(loss, ", ")})
		}
	}
	if d.RefuseRestart != nil {
		if reason := d.RefuseRestart(d.EnforcedConfig, rendered); reason != "" {
			return refuse(&Error{Code: CodeRestartDeferred, Detail: reason})
		}
	}
	dir, err := d.Store.Promote(receipt)
	if err != nil {
		return refuse(err)
	}
	if d.TrustVersion != nil {
		if err := d.TrustVersion(dir); err != nil {
			return refuse(&Error{Code: CodeStateInvalid, Detail: "the bundle version directory is not protected: " + err.Error()})
		}
	}
	// The caller's transaction commits this config before Finish runs.
	// Record which config it is, so SettleRun can tell a run that stopped
	// after the commit (the bundle config enforces) from one that stopped
	// before it (the last good config enforces).
	receipt.ConfigSHA256 = p.ConfigSHA256
	// The config the run started from, in the same durable write: settle
	// tells "this run's transaction installed the bundle bytes" from "the
	// bytes were installed before it" by this record, never by matching
	// bytes or by text the installed config happens to contain (GAP-0484).
	receipt.BaseConfigSHA256 = NoBaseConfig
	if d.EnforcedConfig != nil {
		receipt.BaseConfigSHA256 = sha256Hex(d.EnforcedConfig)
	}
	if d.ConfigPath != "" {
		base, err := configwrite.ReadGenerationState(d.ConfigPath)
		if err == nil {
			receipt.BaseConfigGeneration = base.Generation
			receipt.BaseConfigGenerationKnown = true
		} else if errors.Is(err, fs.ErrNotExist) {
			receipt.BaseConfigGenerationKnown = true
		}
	}
	if err := d.Store.writeReceipt(receipt); err != nil {
		return refuse(&Error{Code: CodeStateInvalid, Detail: "cannot write the policy bundle receipt: " + err.Error()})
	}
	return p, nil
}

// CurrentConfig renders config.yaml of the current bundle against its
// version directory; nil when no bundle is current.
func (d *Driver) CurrentConfig() ([]byte, *Ref, error) {
	st, err := d.Store.LoadState()
	if err != nil || st.Current == nil {
		return nil, nil, err
	}
	b, err := d.Store.ReadVersion(st.Current)
	if err != nil {
		return nil, st.Current, err
	}
	raw, err := RenderConfig(b, d.Store.VersionDir(st.Current.Dir))
	return raw, st.Current, err
}

// Finish settles the receipt of p once the transaction ended. installed is
// the hex SHA-256 of the config.yaml the deployment now holds ("" when it
// cannot be read), failure the lifecycle error codes of a transaction that
// failed (empty when it succeeded). The bundle is confirmed only when the
// transaction installed its config and policy shows the gateway enforcing
// it. If its config was committed but the gateway cannot answer, the receipt
// stays applied for later confirmation. A rejected or uncommitted candidate
// fails (apply_failed, not_confirmed) and the returned error carries the
// code. For a failed candidate, rollback (when not nil) installs the last
// good config again; it returns the digest then enforced and whether the
// rollback finished.
func (d *Driver) Finish(p *Prepared, installed string, failure []string, policy GatewayPolicy, restart bool,
	rollback func() (enforcing string, ok bool)) (State, error) {
	rc := p.Receipt
	if rc == nil || Finished(rc.State) {
		return d.Store.LoadState()
	}
	rc.Restart, rc.RestartRequired = restart, restart
	rc.EnforcingDigest = policy.Digest
	if len(failure) > 0 || installed != p.ConfigSHA256 {
		message := "the ensure transaction did not install the bundle config"
		if len(failure) > 0 {
			// Only codes: lifecycle messages can quote config values.
			message = fmt.Sprintf("the ensure transaction failed (%s)", joinCodes(failure))
		}
		rc.RolledBack = false
		switch owner := d.installedPendingOwner(rc, installed); {
		case owner != nil:
			// The installed config is another receipt's pending commit (a
			// retry that failed before its own commit, or a transaction that
			// put back its unconfirmed predecessor). Neither is a rollback,
			// and the last good config never replaces it here.
			p.InstalledPending = owner
			message += installedPendingMessage(owner)
		case installed != p.ConfigSHA256:
			// The transaction left another config. It is a rollback only once
			// the installed bytes, their generation and the live gateway
			// prove the last good config enforces again.
			rc.RolledBack = d.lastGoodEnforced(rc, installed, &policy)
			if !rc.RolledBack {
				message += "; the deployment does not hold this bundle's config, and the last good config is not proven to enforce again"
			}
		case rollback != nil:
			// The transaction failed after it installed the bundle config:
			// put the last good config back, as for an unconfirmed bundle.
			enforcing, ok := rollback()
			rc.RolledBack = ok
			if enforcing != "" {
				rc.EnforcingDigest = enforcing
			}
			if !ok {
				message += "; putting the last good config back failed"
			}
		}
		return State{}, d.fail(rc, CodeApplyFailed, message)
	}
	rc.EffectivePolicyDigest = policy.EffectiveDigest
	if policy.Unavailable() {
		if generation, committed := d.committedGeneration(rc, installed); committed && digestPattern.MatchString(p.EffectivePolicyDigest) {
			at := d.now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
			if err := d.Store.Advance(rc, StateApplied, func(r *Receipt) {
				r.EffectivePolicyDigest, r.ConfigGeneration, r.ConfigSHA256 = p.EffectivePolicyDigest, generation.Generation, p.ConfigSHA256
				r.AppliedAt, r.Restart, r.RestartRequired = at, restart, restart
			}); err != nil {
				return State{}, err
			}
			return State{}, &Error{Code: CodeNotConfirmed, Detail: "the bundle config is installed, but the gateway is unavailable; its receipt stays applied until the gateway reports the verified policy"}
		}
		return State{}, d.failAfterRollback(p, installed, CodeNotConfirmed,
			"the gateway is unavailable and the bundle transaction was not committed", rollback)
	}
	if err := ConfirmPolicyDigests(rc.ExpectedDigest, policy.EffectiveDigest, policy.Digest, rc.DigestComparable); err != nil {
		return State{}, d.failAfterRollback(p, installed, CodeDigestMismatch, err.Error(), rollback)
	}
	if !policy.Applied || policy.ReloadError != "" || !digestPattern.MatchString(policy.Digest) || !digestPattern.MatchString(policy.EffectiveDigest) {
		reason := "the gateway does not report the effective policy of the bundle config"
		if policy.ReloadError != "" {
			reason = "the gateway rejected the bundle config and keeps enforcing its previous policy"
		}
		return State{}, d.failAfterRollback(p, installed, CodeNotConfirmed, reason, rollback)
	}
	if !d.TransactionApplied(rc, installed, &policy) {
		return State{}, d.failAfterRollback(p, installed, CodeNotConfirmed,
			"the installed generation and gateway do not prove this bundle's transaction; run `defenseclaw enterprise windows ensure --profile standalone --bundle <bundle file>` to apply it again", rollback)
	}
	at := d.now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	if err := d.Store.Advance(rc, StateApplied, func(r *Receipt) {
		r.EffectivePolicyDigest, r.ConfigGeneration, r.ConfigSHA256 = policy.EffectiveDigest, policy.Generation, p.ConfigSHA256
		r.AppliedAt, r.Restart, r.RestartRequired = at, restart, restart
	}); err != nil {
		return State{}, err
	}
	st, err := d.Store.Confirm(rc)
	if err != nil {
		// The apply is proven and the receipt stays applied: a Confirm that
		// stopped after its state write completes from that state on the
		// next run (Store.Settle), one that stopped before it is checked
		// against the gateway again. It is never failed or rolled back here
		// (GAP-0485).
		return st, &Error{Code: CodeStateInvalid, Detail: "the gateway enforces this bundle, but recording its confirmation failed (" +
			boundedDetail(err.Error()) + "); the bundle stays applied: run `defenseclaw enterprise windows ensure --profile standalone` to finish confirming it"}
	}
	return st, nil
}

// SettleRun finishes what an interrupted run left (Store.Settle) and then
// each applied but unconfirmed receipt: confirmed when the deployment holds
// its config and the gateway enforces its digest, pending while the gateway
// cannot answer, and failed(not_confirmed) when live evidence disproves it.
// An applied receipt bundle-state.json already names as current
// (Store.Confirm stopped after its state write) completes from that proof in
// Store.Settle: its apply was proven before the state write, so a gateway
// that is down or not ready now neither fails it nor makes it a rollback
// target while the state still names it. rollback lists the receipts failed
// here whose config is still the installed one: the caller installs the last
// good config again.
//
// Matching config bytes alone do not prove an apply: different signed bundles
// can render identical bytes. A staged receipt also needs the lifecycle's
// durable bundle generation and the gateway's matching bundle identity.
//
// A gateway that cannot be read (GatewayPolicy.Unavailable) proves nothing
// either way: a receipt whose transaction is committed for the installed
// bytes stays open (report.Pending) and the next run settles it, instead of
// failing a bundle for a temporary outage.
func (d *Driver) SettleRun(installedConfig []byte, policy *GatewayPolicy) (report SettleReport, rollback []*Receipt, err error) {
	installed := ""
	if installedConfig != nil {
		installed = sha256Hex(installedConfig)
	}
	completed, interrupted, pending, rollback, err := d.settleCommitted(installedConfig, installed, policy)
	if err != nil {
		return report, rollback, err
	}
	// The text scan only keeps version directories from collection (a
	// conservative over-keep); it is never evidence of a commit.
	keep := VersionDirsNamed(installedConfig, d.Store.BundlesDir)
	open := map[string]bool{}
	for _, item := range pending {
		open[item.receipt.ReceiptID] = true
		keep = append(keep, item.receipt.Dir)
	}
	report, err = d.Store.SettleOpen(open, keep...)
	report.Completed = append(completed, report.Completed...)
	report.Interrupted = append(interrupted, report.Interrupted...)
	for _, item := range pending {
		report.addPending(item.receipt.ReceiptID, item.reason)
	}
	if err != nil {
		return report, rollback, err
	}
	for _, rc := range report.Unconfirmed {
		holds := installed != "" && installed == rc.ConfigSHA256
		_, committed := d.committedGeneration(rc, installed)
		if holds && committed && policy.Unavailable() {
			// Proven by the run that applied it, committed for the installed
			// bytes, and the gateway cannot be read now: retry, never fail.
			report.addPending(rc.ReceiptID, "")
			continue
		}
		if holds && !committed {
			// The applied state records a previous successful transaction.
			// Lost generation evidence cannot disprove that apply.
			report.addPending(rc.ReceiptID, "the signed bundle's committed generation cannot be verified")
			continue
		}
		currentDigest := ""
		comparable := false
		var digestErr error
		if holds && committed && !policy.Unavailable() {
			var verifyErr error
			currentDigest, comparable, verifyErr = d.VerifiedReceiptDigest(rc)
			if verifyErr != nil {
				report.addPending(rc.ReceiptID, "the stored signed bundle's current digest cannot be verified: "+verifyErr.Error())
				continue
			}
			if d.gatewayReportsHistoricalReceipt(rc, installed, policy, currentDigest) {
				report.addPending(rc.ReceiptID, "the gateway still reports this bundle's historical policy digest; retry after the gateway upgrade")
				continue
			}
			digestErr = ConfirmPolicyDigests(rc.ExpectedDigest, currentDigest, policy.Digest, comparable)
		}
		if holds && d.TransactionApplied(rc, installed, policy) && digestErr == nil &&
			policy.EffectiveDigest == currentDigest && policy.Digest == currentDigest {
			if _, err := d.Store.Confirm(rc); err != nil {
				if errors.Is(err, ErrConfirmationPrerequisiteMissing) {
					report.addPending(rc.ReceiptID, err.Error())
					continue
				}
				return report, rollback, err
			}
			report.Completed = append(report.Completed, rc.ReceiptID)
			continue
		}
		if policy != nil {
			rc.EnforcingDigest = policy.Digest
		}
		code := CodeNotConfirmed
		if digestErr != nil {
			code = CodeDigestMismatch
		}
		if err := d.Store.Fail(rc, code, "the run that applied this bundle ended before the gateway confirmed it"); err != nil {
			return report, rollback, err
		}
		if holds {
			rollback = append(rollback, rc)
		}
	}
	return report, rollback, nil
}

func (r *SettleReport) addPending(id, reason string) {
	r.Pending = append(r.Pending, id)
	if reason != "" {
		if r.PendingReasons == nil {
			r.PendingReasons = map[string]string{}
		}
		r.PendingReasons[id] = reason
	}
}

// VerifiedReceiptDigest reads the immutable version named by a pending
// receipt and computes the digest with this build. The receipt's old digest
// stays historical; it is not a comparison target after an upgrade.
func (d *Driver) VerifiedReceiptDigest(rc *Receipt) (string, bool, error) {
	layout, err := StandardDeviceLayout(d.Platform)
	if err != nil {
		return "", false, err
	}
	if d.DeviceLayout != nil {
		layout = *d.DeviceLayout
	}
	return VerifiedReceiptDigest(context.Background(), d.Store, rc, d.Platform, layout, d.ProductVersion,
		d.Store.VersionDir(rc.Dir), d.Digester)
}

// A gateway still running the earlier build can report the receipt's old
// digest while attributing it to the same committed bundle generation. That
// proves the policy has not been displaced, so settle must await the new
// gateway's digest instead of failing and rolling it back.
func (d *Driver) gatewayReportsHistoricalReceipt(rc *Receipt, installed string, policy *GatewayPolicy, currentDigest string) bool {
	if rc == nil || policy == nil {
		return false
	}
	historical := rc.EffectivePolicyDigest
	if rc.State == StateStaged {
		historical = rc.ExpectedDigest
	}
	if (rc.State != StateApplied && rc.State != StateStaged) || currentDigest == historical ||
		!digestPattern.MatchString(historical) || policy.Digest != historical {
		return false
	}
	generation, committed := d.committedGeneration(rc, installed)
	return committed && policy.Generation == generation.Generation && policy.BundleID == rc.BundleID &&
		policy.BundleVersion == rc.Version
}

// TransactionApplied proves that the lifecycle committed this signed bundle,
// the live config still holds those bytes, and the gateway adopted that exact
// generation. Missing or stale evidence never confirms a receipt.
func (d *Driver) TransactionApplied(rc *Receipt, installed string, policy *GatewayPolicy) bool {
	if rc == nil || policy == nil || !policy.Applied || policy.ReloadError != "" || policy.BundleID != rc.BundleID || policy.BundleVersion != rc.Version {
		return false
	}
	generation, committed := d.committedGeneration(rc, installed)
	return committed && policy.Generation == generation.Generation &&
		(rc.State != StateApplied || rc.ConfigGeneration == generation.Generation)
}

// committedGeneration reports whether config.generation.json records the
// lifecycle commit of rc's signed bundle for the installed bytes. Without
// that record the installed bytes are the config the run found, even when
// they equal the bundle's rendered config.
func (d *Driver) committedGeneration(rc *Receipt, installed string) (configwrite.GenerationState, bool) {
	if d.ConfigPath == "" || rc == nil || rc.Principal == "" || rc.SignerKeyID == "" || installed == "" || installed != rc.ConfigSHA256 {
		return configwrite.GenerationState{}, false
	}
	generation, err := configwrite.ReadGenerationState(d.ConfigPath)
	// Matching bytes and bundle identity may belong to an earlier delivery.
	// The generation must advance after this receipt was staged to prove a
	// repeat's own transaction. Legacy receipts without the snapshot are
	// conservative when their starting config had the same bytes.
	if rc.State == StateStaged && rc.BaseConfigSHA256 == installed &&
		(!rc.BaseConfigGenerationKnown || generation.Generation <= rc.BaseConfigGeneration) {
		return configwrite.GenerationState{}, false
	}
	return generation, err == nil && generation.Generation > 0 && generation.ConfigSHA256 == installed &&
		generation.BundleID == rc.BundleID && generation.BundleVersion == rc.Version &&
		generation.SignerKeyID == rc.SignerKeyID && generation.Actor == rc.Principal
}

// CommittedPendingConfig reports an unfinished receipt whose signed config
// is still installed with its lifecycle generation. A staged receipt can
// have that commit when a run stopped before Finish advanced it to applied.
// Callers must not replace those bytes while gateway evidence is unavailable:
// SettleRun can still confirm the receipt when the gateway returns.
func (d *Driver) CommittedPendingConfig(installedConfig []byte) (*Receipt, error) {
	if installedConfig == nil {
		return nil, nil
	}
	receipts, err := d.Store.Unsettled()
	if err != nil {
		return nil, err
	}
	installed := sha256Hex(installedConfig)
	for _, rc := range receipts {
		if rc.State != StateStaged && rc.State != StateApplied {
			continue
		}
		if _, committed := d.committedGeneration(rc, installed); committed {
			return rc, nil
		}
	}
	return nil, nil
}

// settleCommitted settles the staged receipts whose rendered config is the
// installed one (see SettleRun). Only a receipt the lifecycle installed can
// need a rollback: its bundle generation was committed, or the receipt's
// durable base record (BaseConfigSHA256, written before the transaction)
// shows that the installed bytes are not the ones the run started from.
// Identical bytes the run started from ended before the transaction
// installed anything (interrupted), so the installed config stays the last
// good config of the next run. A committed receipt is confirmed only from
// the gateway's live report; with the gateway unavailable it stays open
// (pending).
type settlePending struct {
	receipt *Receipt
	reason  string
}

func (d *Driver) settleCommitted(installedConfig []byte, installed string, policy *GatewayPolicy) (completed, interrupted []string, pending []settlePending, rollback []*Receipt, err error) {
	if installed == "" {
		return nil, nil, nil, nil, nil
	}
	receipts, err := d.Store.Receipts()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, rc := range receipts {
		if rc.State != StateStaged || rc.ConfigSHA256 != installed {
			continue
		}
		if _, committed := d.committedGeneration(rc, installed); !committed {
			if d.installedBeforeRun(rc, installedConfig, installed) {
				if err := d.Store.Fail(rc, CodeInterrupted, "the run that received this bundle ended before its transaction installed it; the installed config kept enforcing"); err != nil {
					return completed, interrupted, pending, rollback, err
				}
				interrupted = append(interrupted, rc.ReceiptID)
				continue
			}
			// The run installed these bytes without a commit record: never
			// confirmed, and not a last good config.
			if err := d.Store.Fail(rc, CodeNotConfirmed, "the interrupted run installed this bundle's config without committing its transaction; run `defenseclaw enterprise windows ensure --profile standalone --bundle <bundle file>` to apply it again"); err != nil {
				return completed, interrupted, pending, rollback, err
			}
			rollback = append(rollback, rc)
			continue
		}
		if policy.Unavailable() {
			pending = append(pending, settlePending{receipt: rc})
			continue
		}
		currentDigest, comparable, verifyErr := d.VerifiedReceiptDigest(rc)
		if verifyErr != nil {
			pending = append(pending, settlePending{receipt: rc, reason: "the stored signed bundle's current digest cannot be verified: " + verifyErr.Error()})
			continue
		}
		if d.gatewayReportsHistoricalReceipt(rc, installed, policy, currentDigest) {
			// The committed generation and the old signed digest prove the
			// gateway adopted this bundle, even though the new build cannot
			// yet compare the older gateway with its current digest.
			at := d.now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
			if err := d.Store.Advance(rc, StateApplied, func(r *Receipt) {
				r.EffectivePolicyDigest, r.ConfigGeneration, r.AppliedAt = policy.Digest, policy.Generation, at
			}); err != nil {
				return completed, interrupted, pending, rollback, err
			}
			pending = append(pending, settlePending{receipt: rc,
				reason: "the gateway still reports this bundle's historical policy digest; retry after the gateway upgrade"})
			continue
		}
		digestErr := ConfirmPolicyDigests(rc.ExpectedDigest, currentDigest, policy.Digest, comparable)
		enforces := d.TransactionApplied(rc, installed, policy) && digestPattern.MatchString(policy.Digest) &&
			policy.EffectiveDigest == currentDigest && policy.Digest == currentDigest && digestErr == nil
		if enforces {
			at := d.now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
			if err := d.Store.Advance(rc, StateApplied, func(r *Receipt) {
				r.EffectivePolicyDigest, r.ConfigGeneration, r.AppliedAt = policy.EffectiveDigest, policy.Generation, at
			}); err != nil {
				return completed, interrupted, pending, rollback, err
			}
			// A Confirm error keeps the proven receipt applied for the next
			// run (Store.Settle completes it from a state ref Confirm wrote);
			// it never falls through to fail it or name it for rollback
			// (GAP-0485).
			if _, err := d.Store.Confirm(rc); err != nil {
				if errors.Is(err, ErrConfirmationPrerequisiteMissing) {
					pending = append(pending, settlePending{receipt: rc, reason: err.Error()})
					continue
				}
				return completed, interrupted, pending, rollback, fmt.Errorf("confirm the proven bundle %s version %d: %w", rc.BundleID, rc.Version, err)
			}
			completed = append(completed, rc.ReceiptID)
			continue
		}
		rc.EnforcingDigest = policy.Digest
		code := CodeNotConfirmed
		if digestErr != nil {
			code = CodeDigestMismatch
		}
		if err := d.Store.Fail(rc, code, "the interrupted run has no proven bundle apply and gateway confirmation; run `defenseclaw enterprise windows ensure --profile standalone --bundle <bundle file>` to apply it again"); err != nil {
			return completed, interrupted, pending, rollback, err
		}
		rollback = append(rollback, rc)
	}
	return completed, interrupted, pending, rollback, nil
}

// installedBeforeRun reports whether the installed config, whose bytes are
// rc's rendered config, was already installed when the run that staged rc
// started. The receipt's base record decides; a receipt written before that
// record existed falls back to the version directories the installed
// config's YAML values (never its comments) name: only rc's own config can
// point into rc's directory.
func (d *Driver) installedBeforeRun(rc *Receipt, installedConfig []byte, installed string) bool {
	switch rc.BaseConfigSHA256 {
	case "":
		return !slices.Contains(VersionDirsInValues(installedConfig, d.Store.BundlesDir), rc.Dir)
	case NoBaseConfig:
		return false
	default:
		return rc.BaseConfigSHA256 == installed
	}
}

func (d *Driver) failAfterRollback(p *Prepared, installed string, code Code, message string, rollback func() (string, bool)) error {
	rc := p.Receipt
	if owner := d.installedPendingOwner(rc, installed); owner != nil {
		// This run committed nothing over another receipt's pending config:
		// the last good config must not replace it (see Finish).
		rc.RolledBack = false
		p.InstalledPending = owner
		return d.fail(rc, code, message+installedPendingMessage(owner))
	}
	if rollback != nil {
		enforcing, ok := rollback()
		rc.RolledBack = ok
		if enforcing != "" {
			rc.EnforcingDigest = enforcing
		}
		if !ok {
			message += "; putting the last good config back failed"
		}
	}
	return d.fail(rc, code, message)
}

// installedPendingOwner is the other unfinished receipt whose committed
// generation holds the installed config while rc's own transaction committed
// nothing for it, or nil.
func (d *Driver) installedPendingOwner(rc *Receipt, installed string) *Receipt {
	if rc == nil || installed == "" {
		return nil
	}
	if _, committed := d.committedGeneration(rc, installed); committed {
		return nil
	}
	receipts, err := d.Store.Unsettled()
	if err != nil {
		return nil
	}
	for _, other := range receipts {
		if other.ReceiptID == rc.ReceiptID || (other.State != StateStaged && other.State != StateApplied) {
			continue
		}
		if _, committed := d.committedGeneration(other, installed); committed {
			return other
		}
	}
	return nil
}

func installedPendingMessage(owner *Receipt) string {
	return fmt.Sprintf("; the deployment holds policy bundle %s version %d (receipt %s), which an earlier run committed and the gateway has not confirmed: "+
		"it stays installed and pending, nothing was rolled back, and the next lifecycle run settles it", owner.BundleID, owner.Version, owner.ReceiptID)
}

// lastGoodEnforced proves that the installed config is the last good one and
// that the live gateway enforces it: the confirmed bundle's rendered config
// under its own generation record, or, with no confirmed bundle, the config
// rc's run started from under a record that names no bundle. No config at
// all is the last good state of a run that started with none.
func (d *Driver) lastGoodEnforced(rc *Receipt, installed string, policy *GatewayPolicy) bool {
	st, err := d.Store.LoadState()
	if err != nil {
		return false
	}
	var id, signer string
	var version uint64
	if st.Current != nil {
		raw, ref, err := d.CurrentConfig()
		if err != nil || ref == nil || installed == "" || sha256Hex(raw) != installed {
			return false
		}
		id, version, signer = ref.BundleID, ref.Version, ref.SignerKeyID
	} else if rc.BaseConfigSHA256 == NoBaseConfig {
		return installed == ""
	} else if rc.BaseConfigSHA256 == "" || rc.BaseConfigSHA256 != installed {
		return false
	}
	if d.ConfigPath == "" || policy == nil || policy.Unavailable() || !policy.Applied || policy.ReloadError != "" ||
		!digestPattern.MatchString(policy.Digest) || policy.Digest != policy.EffectiveDigest ||
		policy.BundleID != id || policy.BundleVersion != version {
		return false
	}
	record, err := configwrite.ReadGenerationState(d.ConfigPath)
	return err == nil && record.Generation > 0 && record.ConfigSHA256 == installed && policy.Generation == record.Generation &&
		record.BundleID == id && record.BundleVersion == version && record.SignerKeyID == signer
}

func (d *Driver) fail(rc *Receipt, code Code, message string) error {
	if err := d.Store.Fail(rc, code, message); err != nil {
		return fmt.Errorf("record the failed bundle receipt: %w", err)
	}
	return &Error{Code: code, Detail: message}
}

// RestartDeferralReason is the restart_deferred detail for the settings of
// a config change that restart the gateway (restart), or for a change whose
// effect cannot be told (unknown: no installed config to compare); "" when
// the change applies without a restart.
func RestartDeferralReason(restart []string, unknown bool) string {
	switch {
	case unknown:
		return "--defer-restart: cannot tell whether this bundle restarts the gateway (no installed config to compare), so it is not applied; apply it without --defer-restart in a maintenance window"
	case len(restart) > 0:
		return "--defer-restart: this bundle changes settings that restart the gateway (" + boundedDetail(strings.Join(restart, ", ")) + "), so it is not applied; apply it without --defer-restart in a maintenance window"
	}
	return ""
}

func joinCodes(codes []string) string {
	out := ""
	seen := map[string]bool{}
	for _, c := range codes {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if out != "" {
			out += ", "
		}
		out += c
	}
	return out
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
