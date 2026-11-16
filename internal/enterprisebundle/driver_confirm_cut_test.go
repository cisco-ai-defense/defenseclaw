// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// A run that stopped inside Store.Confirm, after bundle-state.json named the
// proven bundle B and before B's receipt was confirmed, completes B from that
// state on recovery. B's apply was proven before the state write, so recovery
// needs no live readback: a gateway that is down, not ready or reloading at
// recovery neither fails B nor names B as the rollback target while the state
// still names B as current, and the prior bundle A stays the last good one.
func TestDriverSettleRunCompletesAProvenBundleAfterAConfirmCut(t *testing.T) {
	for _, tc := range []struct {
		name string
		// policy is what the gateway reports at recovery, from B's proof.
		policy func(proven enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy
		// noConfig: the installed config cannot be read at recovery.
		noConfig bool
	}{
		{name: "gateway unreachable", policy: func(enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return nil }},
		{name: "gateway not ready", policy: func(enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy {
			return &enterprisebundle.GatewayPolicy{}
		}},
		{name: "gateway reloading", policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy {
			p.Applied, p.ReloadError = false, "reload in progress"
			return &p
		}},
		{name: "gateway reports no bundle identity", policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy {
			p.BundleID, p.BundleVersion, p.Generation = "", 0, 0
			return &p
		}},
		{name: "installed config unreadable", noConfig: true, policy: func(enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return nil }},
		{name: "gateway still proves it", policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return &p }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), nil)
			d := driverFor(t, f)
			a, err := d.Prepare(t.Context(), f.bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.Finish(a, a.ConfigSHA256, nil, installPreparedBundle(t, d, a), false, nil); err != nil {
				t.Fatal(err)
			}
			f.in.Version++
			f.in.BundleID = "b-01JA0000000000000000000043"
			_, raw, err := enterprisebundle.Compose(t.Context(), f.in)
			if err != nil {
				t.Fatal(err)
			}
			b, err := d.Prepare(t.Context(), f.signed(t, raw), nil)
			if err != nil {
				t.Fatal(err)
			}
			proven := installPreparedBundle(t, d, b)
			// The process stops after Confirm saved bundle-state.json naming B
			// and before it wrote B's confirmed receipt.
			receiptsDir := filepath.Join(d.Store.LifecycleDir, enterprisebundle.ReceiptsDirName)
			d.Store.EnsurePrivateDirectory = func(path string) error {
				if st, err := d.Store.LoadState(); path == receiptsDir && err == nil && st.Current != nil && st.Current.BundleID == b.Receipt.BundleID {
					return errors.New("process stopped")
				}
				return os.MkdirAll(path, 0o700)
			}
			if _, err := d.Finish(b, b.ConfigSHA256, nil, proven, false, nil); err == nil {
				t.Fatal("the cut did not stop Confirm before the receipt write")
			}
			d.Store.EnsurePrivateDirectory = nil
			if rc := receiptOf(t, d, b.Receipt.ReceiptID); rc.State != enterprisebundle.StateApplied {
				t.Fatalf("cut left receipt %s, want applied", rc.State)
			}

			installed := b.Config
			if tc.noConfig {
				installed = nil
			}
			report, rollback, err := d.SettleRun(installed, tc.policy(proven))
			if err != nil {
				t.Fatal(err)
			}
			if len(rollback) != 0 {
				t.Fatalf("the proven current bundle was named for a rollback: %+v", rollback[0])
			}
			if !slices.Contains(report.Completed, b.Receipt.ReceiptID) || len(report.Interrupted) != 0 || len(report.Unconfirmed) != 0 {
				t.Fatalf("report = %+v, want B completed", report)
			}
			rc := receiptOf(t, d, b.Receipt.ReceiptID)
			if rc.State != enterprisebundle.StateConfirmed || rc.ErrorCode != "" || rc.EnforcingDigest != rc.EffectivePolicyDigest {
				t.Fatalf("receipt = %s %s, enforcing %q effective %q", rc.State, rc.ErrorCode, rc.EnforcingDigest, rc.EffectivePolicyDigest)
			}
			st, err := d.Store.LoadState()
			if err != nil || st.Current == nil || st.Current.Dir != b.Receipt.Dir || st.LastGood == nil ||
				st.LastGood.Dir != a.Receipt.Dir || st.Floor != b.Receipt.Version || rc.ConfirmedAt != st.Current.ConfirmedAt {
				t.Fatalf("state = %+v, %v", st, err)
			}
		})
	}
}

// The current-state ref completes only the applied receipt Confirm wrote it
// for: the same bundle under another receipt's version directory, or a ref
// whose proof fields differ from the receipt's, is no proof of that receipt's
// apply, so the receipt goes back to the caller for the live check.
func TestStoreSettleCompletesOnlyTheReceiptTheStateNames(t *testing.T) {
	for _, tc := range []struct {
		name     string
		edit     func(ref *enterprisebundle.Ref)
		complete bool
	}{
		{name: "the ref Confirm wrote", edit: func(*enterprisebundle.Ref) {}, complete: true},
		{name: "another receipt of the same bundle", edit: func(ref *enterprisebundle.Ref) {
			ref.Dir = enterprisebundle.VersionDirName(ref.Version, ref.BundleID)
		}},
		{name: "another generation", edit: func(ref *enterprisebundle.Ref) { ref.ConfigGeneration++ }},
		{name: "another effective digest", edit: func(ref *enterprisebundle.Ref) {
			ref.EffectivePolicyDigest = "sha256:" + fmt.Sprintf("%064d", 7)
		}},
		{name: "another signer", edit: func(ref *enterprisebundle.Ref) { ref.SignerKeyID = "k2" }},
		{name: "no proof fields", edit: func(ref *enterprisebundle.Ref) { ref.EffectivePolicyDigest, ref.ConfigGeneration = "", 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), nil)
			d := driverFor(t, f)
			p, err := d.Prepare(t.Context(), f.bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			proven := installPreparedBundle(t, d, p)
			if err := d.Store.Advance(p.Receipt, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
				rc.EffectivePolicyDigest, rc.ConfigGeneration = proven.EffectiveDigest, proven.Generation
			}); err != nil {
				t.Fatal(err)
			}
			rc := p.Receipt
			ref := enterprisebundle.Ref{BundleID: rc.BundleID, Version: rc.Version, ManifestSHA256: rc.ManifestSHA256, Dir: rc.Dir,
				SignerKeyID: rc.SignerKeyID, EffectivePolicyDigest: rc.EffectivePolicyDigest, ConfigGeneration: rc.ConfigGeneration,
				ConfirmedAt: "2026-06-01T00:00:00.000Z"}
			tc.edit(&ref)
			raw, err := json.Marshal(enterprisebundle.State{SchemaVersion: enterprisebundle.StateSchemaVersion, Current: &ref, Floor: rc.Version})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(d.Store.StatePath(), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			report, err := d.Store.Settle()
			if err != nil {
				t.Fatal(err)
			}
			completed := slices.Contains(report.Completed, rc.ReceiptID)
			unconfirmed := len(report.Unconfirmed) == 1 && report.Unconfirmed[0].ReceiptID == rc.ReceiptID
			if completed != tc.complete || unconfirmed == tc.complete {
				t.Fatalf("completed = %v, unconfirmed = %v, want completed %v", completed, unconfirmed, tc.complete)
			}
			if got := receiptOf(t, d, rc.ReceiptID); tc.complete && (got.State != enterprisebundle.StateConfirmed || got.ConfirmedAt != ref.ConfirmedAt) {
				t.Fatalf("receipt = %s at %q", got.State, got.ConfirmedAt)
			}
		})
	}
}

func TestDriverSettleRunKeepsNamedReceiptPendingWithoutConfirmationPrerequisite(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	p, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	proven := installPreparedBundle(t, d, p)
	if err := d.Store.Advance(p.Receipt, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
		rc.EffectivePolicyDigest, rc.ConfigGeneration = proven.EffectiveDigest, proven.Generation
	}); err != nil {
		t.Fatal(err)
	}
	rc := p.Receipt
	ref := enterprisebundle.Ref{BundleID: rc.BundleID, Version: rc.Version, ManifestSHA256: rc.ManifestSHA256, Dir: rc.Dir,
		SignerKeyID: rc.SignerKeyID, EffectivePolicyDigest: rc.EffectivePolicyDigest, ConfigGeneration: rc.ConfigGeneration,
		ConfirmedAt: "2026-06-01T00:00:00.000Z"}
	raw, err := json.Marshal(enterprisebundle.State{SchemaVersion: enterprisebundle.StateSchemaVersion, Current: &ref, Floor: rc.Version})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.Store.StatePath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	d.Store.BeforeConfirm = func(*enterprisebundle.Receipt) error {
		return fmt.Errorf("legacy trust anchors absent: %w", enterprisebundle.ErrConfirmationPrerequisiteMissing)
	}
	for range 2 {
		report, rollback, err := d.SettleRun(p.Config, &proven)
		if err != nil {
			t.Fatalf("settle refused a pending receipt: %v", err)
		}
		if len(rollback) != 0 || !slices.Contains(report.Pending, rc.ReceiptID) || slices.Contains(report.Completed, rc.ReceiptID) {
			t.Fatalf("settle report = %+v, rollback = %+v", report, rollback)
		}
		if got := receiptOf(t, d, rc.ReceiptID); got.State != enterprisebundle.StateApplied || got.ConfirmedAt != "" {
			t.Fatalf("named receipt was confirmed without anchors: %+v", got)
		}
	}
}

// A state ref was written only after the apply was proved. Losing the
// receipt's trust-anchor stage does not undo that proof, even when a later
// gateway readback or the installed config is unavailable or has changed.
// Settlement must not fail or roll back that state-named receipt.
func TestDriverSettleRunNeverRollsBackNamedReceiptMissingAnchors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy func(enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy
		absent bool
	}{
		{name: "gateway unavailable", policy: func(enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return nil }},
		{name: "gateway changed", policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy {
			p.Digest, p.EffectiveDigest = "sha256:"+fmt.Sprintf("%064d", 7), "sha256:"+fmt.Sprintf("%064d", 7)
			return &p
		}},
		{name: "installed config changed", policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return &p }, absent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), nil)
			d := driverFor(t, f)
			// The production Unix store seals for its service group. This
			// receipt test does not exercise file modes; keep its stage
			// movable on macOS, where 0555 directories cannot be renamed.
			d.Store.SealVersion = func(string) error { return nil }
			p, err := d.Prepare(t.Context(), f.bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			proven := installPreparedBundle(t, d, p)
			if err := d.Store.Advance(p.Receipt, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
				rc.EffectivePolicyDigest, rc.ConfigGeneration = proven.EffectiveDigest, proven.Generation
			}); err != nil {
				t.Fatal(err)
			}
			rc := p.Receipt
			ref := enterprisebundle.Ref{BundleID: rc.BundleID, Version: rc.Version, ManifestSHA256: rc.ManifestSHA256, Dir: rc.Dir,
				SignerKeyID: rc.SignerKeyID, EffectivePolicyDigest: rc.EffectivePolicyDigest, ConfigGeneration: rc.ConfigGeneration,
				ConfirmedAt: "2026-06-01T00:00:00.000Z"}
			raw, err := json.Marshal(enterprisebundle.State{SchemaVersion: enterprisebundle.StateSchemaVersion, Current: &ref, Floor: rc.Version})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(d.Store.StatePath(), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			d.Store.BeforeConfirm = func(*enterprisebundle.Receipt) error {
				return fmt.Errorf("staged trust anchors missing: %w", enterprisebundle.ErrConfirmationPrerequisiteMissing)
			}
			installed := p.Config
			if tc.absent {
				installed = nil
			}
			for range 2 {
				report, rollback, err := d.SettleRun(installed, tc.policy(proven))
				if err != nil {
					t.Fatal(err)
				}
				if len(rollback) != 0 || !slices.Contains(report.Pending, rc.ReceiptID) || len(report.Completed) != 0 {
					t.Fatalf("report = %+v, rollback = %+v", report, rollback)
				}
				if reason := report.PendingReasons[rc.ReceiptID]; !strings.Contains(reason, "staged trust anchors missing") {
					t.Fatalf("pending reason = %q, report = %+v", reason, report)
				}
				if got := receiptOf(t, d, rc.ReceiptID); got.State != enterprisebundle.StateApplied || got.ErrorCode != "" {
					t.Fatalf("anchorless receipt changed: %+v", got)
				}
			}
		})
	}
}

func receiptOf(t *testing.T, d *enterprisebundle.Driver, id string) *enterprisebundle.Receipt {
	t.Helper()
	receipts, err := d.Store.Receipts()
	if err != nil {
		t.Fatal(err)
	}
	for _, rc := range receipts {
		if rc.ReceiptID == id {
			return rc
		}
	}
	t.Fatalf("no receipt %s", id)
	return nil
}
