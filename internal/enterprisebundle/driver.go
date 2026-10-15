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
	"fmt"
	"strings"
	"time"
)

// Driver applies a bundle around a lifecycle transaction it does not run
// itself: the Windows lifecycle, whose transaction is the installer module.
// Prepare receives the bundle (receipt), stages it, verifies the staged copy
// (never the path it was delivered at), promotes it to its immutable version
// directory and renders its config.yaml against that directory. The caller
// then installs that config with its own ensure transaction, which rolls
// back on its own failure. Finish confirms the bundle only once the running
// gateway reports the effective policy of the installed config with no
// reload error; anything else fails the receipt, and the caller installs
// the last good config again. Until the confirm, bundle-state.json still
// names the last good bundle, so a run that stops in between is settled by
// SettleRun at the start of the next one.
type Driver struct {
	Store       *Store
	AnchorsPath string
	// AnchorTrust is the device trust check of the anchor file.
	AnchorTrust    func(path string) error
	Platform       string
	ProductVersion string
	DeviceLayout   *DeviceLayout
	Now            func() time.Time
	// SecretPresent reports whether the device holds a credential.
	SecretPresent func(name string) (bool, error)
	Digester      PolicyDigester
	// TrustVersion checks the promoted version directory before its config
	// is rendered (Windows: owned by SYSTEM or Administrators, no write
	// entry for another account); nil skips it.
	TrustVersion func(dir string) error
	// EnforcedConfig is the currently installed, enforcing config. A nil
	// value means this is the first bundle on a device with no config.
	EnforcedConfig       []byte
	RefuseCapabilityLoss bool
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
	// AlreadyApplied is a repeated delivery of the current bundle: its
	// receipt was discarded and Config is the current bundle config.
	AlreadyApplied bool
	Warnings       []Warning
}

// GatewayPolicy is what the running gateway reports after the transaction.
type GatewayPolicy struct {
	// EffectiveDigest is computed from the installed config; Digest is what
	// the running gateway reports. They must agree before confirmation.
	EffectiveDigest string
	Digest          string
	Generation      uint64
	ReloadError     string
	// Applied is true when Digest is the effective policy digest of the
	// installed config.
	Applied bool
}

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
	receipt, err := d.Store.Receive(id, version)
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
		return refuse(&Error{Code: CodeArchiveInvalid, Detail: "cannot stage the bundle: " + err.Error()})
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
		ProductVersion: d.ProductVersion, DeviceLayout: d.DeviceLayout, SecretPresent: d.SecretPresent,
		Stage:    func(*Bundle) (string, error) { return staging, nil },
		Digester: d.Digester,
	})
	p.FloorSource = res.FloorSource
	p.Warnings = res.Warnings
	if err != nil {
		return refuse(err)
	}
	p.Manifest = res.Manifest
	if res.AlreadyApplied {
		if err := d.Store.Discard(receipt); err != nil {
			p.Warnings = append(p.Warnings, Warning{Code: "bundle_state_unreadable",
				Message: "could not remove the receipt of the repeated delivery: " + err.Error()})
		}
		raw, _, err := d.CurrentConfig()
		if err != nil {
			return p, &Error{Code: CodeStateInvalid, Detail: "cannot read the current policy bundle: " + err.Error()}
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
		rc.ChangeSummary = m.ChangeSummary
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
// it; otherwise the receipt fails (apply_failed, not_confirmed) and the
// returned error carries the code. When the bundle config was installed but
// not confirmed, rollback (when not nil) installs the last good config again
// before the receipt fails; it returns the digest the gateway then enforces
// and whether the rollback finished.
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
		rc.RolledBack = installed != p.ConfigSHA256
		if !rc.RolledBack && rollback != nil {
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
	if err := ConfirmPolicyDigests(rc.ExpectedDigest, policy.EffectiveDigest, policy.Digest, rc.DigestComparable); err != nil {
		return State{}, d.failAfterRollback(rc, CodeDigestMismatch, err.Error(), rollback)
	}
	if !policy.Applied || policy.ReloadError != "" || !digestPattern.MatchString(policy.Digest) || !digestPattern.MatchString(policy.EffectiveDigest) {
		reason := "the gateway does not report the effective policy of the bundle config"
		if policy.ReloadError != "" {
			reason = "the gateway rejected the bundle config and keeps enforcing its previous policy"
		}
		return State{}, d.failAfterRollback(rc, CodeNotConfirmed, reason, rollback)
	}
	at := d.now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	if err := d.Store.Advance(rc, StateApplied, func(r *Receipt) {
		r.EffectivePolicyDigest, r.ConfigGeneration, r.ConfigSHA256 = policy.EffectiveDigest, policy.Generation, p.ConfigSHA256
		r.AppliedAt, r.Restart, r.RestartRequired = at, restart, restart
	}); err != nil {
		return State{}, err
	}
	return d.Store.Confirm(rc)
}

// SettleRun finishes what an interrupted run left (Store.Settle) and then
// each applied but unconfirmed receipt: confirmed when the deployment holds
// its config and the gateway enforces its digest, failed(not_confirmed)
// otherwise. rollback lists the receipts failed here whose config is still
// the installed one: the caller installs the last good config again.
//
// A staged receipt whose config the deployment holds was committed by a
// transaction whose run stopped before Finish: it is confirmed when the
// gateway enforces the installed config and failed (not_confirmed, named
// for a rollback) otherwise, never reported as an apply that did not happen.
func (d *Driver) SettleRun(installedConfig []byte, policy *GatewayPolicy) (report SettleReport, rollback []*Receipt, err error) {
	installedDirs := VersionDirsNamed(installedConfig, d.Store.BundlesDir)
	installed := ""
	if installedConfig != nil {
		installed = sha256Hex(installedConfig)
	}
	completed, rollback, err := d.settleCommitted(installed, policy)
	if err != nil {
		return report, rollback, err
	}
	report, err = d.Store.Settle(installedDirs...)
	report.Completed = append(completed, report.Completed...)
	if err != nil {
		return report, rollback, err
	}
	for _, rc := range report.Unconfirmed {
		holds := installed != "" && installed == rc.ConfigSHA256
		var digestErr error
		if policy != nil {
			digestErr = ConfirmPolicyDigests(rc.ExpectedDigest, rc.EffectivePolicyDigest, policy.Digest, rc.DigestComparable)
		}
		if holds && policy != nil && policy.Applied && policy.ReloadError == "" && digestErr == nil && policy.Digest == rc.EffectivePolicyDigest {
			if _, err := d.Store.Confirm(rc); err != nil {
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

// settleCommitted settles the staged receipts whose rendered config is the
// installed one (see SettleRun).
func (d *Driver) settleCommitted(installed string, policy *GatewayPolicy) (completed []string, rollback []*Receipt, err error) {
	if installed == "" {
		return nil, nil, nil
	}
	receipts, err := d.Store.Receipts()
	if err != nil {
		return nil, nil, err
	}
	for _, rc := range receipts {
		if rc.State != StateStaged || rc.ConfigSHA256 != installed {
			continue
		}
		var digestErr error
		if policy != nil {
			digestErr = ConfirmPolicyDigests(rc.ExpectedDigest, policy.EffectiveDigest, policy.Digest, rc.DigestComparable)
		}
		enforces := policy != nil && policy.Applied && policy.ReloadError == "" && digestPattern.MatchString(policy.Digest) &&
			digestPattern.MatchString(policy.EffectiveDigest) && digestErr == nil
		if enforces {
			at := d.now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
			if err := d.Store.Advance(rc, StateApplied, func(r *Receipt) {
				r.EffectivePolicyDigest, r.ConfigGeneration, r.AppliedAt = policy.EffectiveDigest, policy.Generation, at
			}); err != nil {
				return completed, rollback, err
			}
			if _, err := d.Store.Confirm(rc); err == nil {
				completed = append(completed, rc.ReceiptID)
				continue
			}
		}
		if policy != nil {
			rc.EnforcingDigest = policy.Digest
		}
		code := CodeNotConfirmed
		if digestErr != nil {
			code = CodeDigestMismatch
		}
		if err := d.Store.Fail(rc, code, "the run that installed this bundle config ended before the gateway confirmed it"); err != nil {
			return completed, rollback, err
		}
		rollback = append(rollback, rc)
	}
	return completed, rollback, nil
}

func (d *Driver) failAfterRollback(rc *Receipt, code Code, message string, rollback func() (string, bool)) error {
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

func (d *Driver) fail(rc *Receipt, code Code, message string) error {
	if err := d.Store.Fail(rc, code, message); err != nil {
		return fmt.Errorf("record the failed bundle receipt: %w", err)
	}
	return &Error{Code: code, Detail: message}
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
