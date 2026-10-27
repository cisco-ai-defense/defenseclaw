// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"bytes"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// settingsOnly is the test bundle config without the files it names under
// its version directory, so every receipt of one signed bundle renders the
// same bytes; guardrailMode tells two such bundles apart.
func settingsOnly(t *testing.T, guardrailMode string) string {
	t.Helper()
	cfg := strings.Replace(bundleConfig(t), "  signature_packs:\n    - discovery/signature-packs/team.json\n  confidence_policy_path: discovery/confidence.yaml\n", "", 1)
	return strings.Replace(cfg, "guardrail:\n  enabled: true\n  mode: observe\n", "guardrail:\n  enabled: true\n  mode: "+guardrailMode+"\n", 1)
}

// variant is another bundle of f's tenant with configYAML, signed by f's key.
func (f *fixture) variant(t *testing.T, configYAML string, edit func(*enterprisebundle.ComposeInput)) *enterprisebundle.Bundle {
	t.Helper()
	root, b := writeBundle(t, configYAML)
	in := f.in
	in.Bundle, in.Root = b, root
	if edit != nil {
		edit(&in)
	}
	_, raw, err := enterprisebundle.Compose(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := enterprisebundle.Sign(raw, f.key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	sigRaw, err := sig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &enterprisebundle.Bundle{Manifest: raw, Signature: sigRaw, Files: maps.Clone(b.Files)}
}

// pendingRun is a device whose settings-only bundle A (version 5) is
// confirmed. With a pending state, bundle B (version 6) committed its config
// over A and the gateway went down before it confirmed: the receipt stays
// staged (the run died before Finish) or applied (Finish saw the outage),
// as SettleRun keeps it pending.
type pendingRun struct {
	f                *fixture
	d                *enterprisebundle.Driver
	a, b             *enterprisebundle.Prepared
	aPolicy, bPolicy enterprisebundle.GatewayPolicy
	bBundle          *enterprisebundle.Bundle
}

func newPendingRun(t *testing.T, pendingState string) *pendingRun {
	t.Helper()
	r := &pendingRun{f: newFixture(t, settingsOnly(t, "observe"), nil)}
	r.d = driverFor(t, r.f)
	var err error
	if r.a, err = r.d.Prepare(t.Context(), r.f.bundle, nil); err != nil {
		t.Fatal(err)
	}
	r.aPolicy = installPreparedBundle(t, r.d, r.a)
	if _, err := r.d.Finish(r.a, r.a.ConfigSHA256, nil, r.aPolicy, false, nil); err != nil {
		t.Fatal(err)
	}
	r.d.EnforcedConfig = r.a.Config
	if pendingState == "" {
		return r
	}
	r.bBundle = r.f.variant(t, settingsOnly(t, "action"), func(in *enterprisebundle.ComposeInput) { in.Version, in.ChangeSummary = 6, "pending" })
	if r.b, err = r.d.Prepare(t.Context(), r.bBundle, nil); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(r.a.Config, r.b.Config) {
		t.Fatal("setup: A and B render the same config")
	}
	r.bPolicy = installPreparedBundle(t, r.d, r.b)
	if pendingState == enterprisebundle.StateApplied {
		if _, err := r.d.Finish(r.b, r.b.ConfigSHA256, nil, enterprisebundle.GatewayPolicy{}, false, nil); enterprisebundle.CodeOf(err) != enterprisebundle.CodeNotConfirmed {
			t.Fatalf("setup: the outage did not keep B applied: %v", err)
		}
	}
	report, rollback, err := r.d.SettleRun(r.b.Config, nil)
	if err != nil || len(report.Pending) != 1 || len(rollback) != 0 || r.unsettled(t).State != pendingState {
		t.Fatalf("setup: report=%+v rollback=%+v error=%v", report, rollback, err)
	}
	r.d.EnforcedConfig = r.b.Config
	return r
}

// unsettled is the one receipt no run confirmed or failed.
func (r *pendingRun) unsettled(t *testing.T) *enterprisebundle.Receipt {
	t.Helper()
	receipts, err := r.d.Store.Unsettled()
	if err != nil || len(receipts) != 1 {
		t.Fatalf("unsettled receipts = %+v, %v", receipts, err)
	}
	return receipts[0]
}

// A retry of a bundle whose committed receipt waits behind a gateway outage
// renders the same bytes as that receipt. The generation attribution of those
// bytes stays that bundle's (it never fails as "multiple staged policy bundles
// match"), and however the retry ends before its own commit, the last good
// bundle is never put back over the pending commit: the pending receipt keeps
// its state and still confirms once the gateway reports it.
func TestDriverRetryOfAPendingBundleKeepsItsCommittedConfig(t *testing.T) {
	for _, pendingState := range []string{enterprisebundle.StateStaged, enterprisebundle.StateApplied} {
		for _, outcome := range []string{"transaction fails before its commit", "gateway still unavailable", "gateway reports the pending commit"} {
			t.Run(pendingState+"/"+outcome, func(t *testing.T) {
				r := newPendingRun(t, pendingState)
				retry, err := r.d.Prepare(t.Context(), r.bBundle, nil)
				if err != nil || retry.Receipt == nil {
					t.Fatalf("retry prepare: %+v, %v", retry, err)
				}
				if !bytes.Equal(retry.Config, r.b.Config) {
					t.Fatal("regression requires identical rendered configs")
				}
				opt, ok, err := r.d.ConfigGenerationOptions(retry.Config)
				if err != nil || !ok || opt.Bundle.ID != r.b.Receipt.BundleID || opt.Bundle.Version != r.b.Receipt.Version || opt.Actor != r.b.Receipt.Principal {
					t.Fatalf("generation attribution of the retried bytes = %+v, %v, %v", opt, ok, err)
				}
				putBack := false
				rollback := func() (string, bool) { putBack = true; return r.aPolicy.Digest, true }
				failure, policy, want := []string(nil), enterprisebundle.GatewayPolicy{}, enterprisebundle.CodeNotConfirmed
				switch outcome {
				case "transaction fails before its commit":
					failure, want = []string{"lifecycle_error"}, enterprisebundle.CodeApplyFailed
				case "gateway reports the pending commit":
					policy = r.bPolicy
				}
				if _, err := r.d.Finish(retry, retry.ConfigSHA256, failure, policy, false, rollback); enterprisebundle.CodeOf(err) != want {
					t.Fatalf("finish = %v, want %s", err, want)
				}
				if putBack || retry.Receipt.RolledBack || retry.Receipt.State != enterprisebundle.StateFailed ||
					retry.InstalledPending == nil || retry.InstalledPending.ReceiptID != r.b.Receipt.ReceiptID ||
					!strings.Contains(retry.Receipt.ErrorMessage, r.b.Receipt.ReceiptID) {
					t.Fatalf("the retry replaced or misreported the pending commit: put back=%v receipt=%+v pending=%+v", putBack, retry.Receipt, retry.InstalledPending)
				}
				if got := r.unsettled(t); got.ReceiptID != r.b.Receipt.ReceiptID || got.State != pendingState {
					t.Fatalf("pending receipt = %+v", got)
				}
				state, err := r.d.Store.LoadState()
				if err != nil || state.Current == nil || state.Current.Version != r.a.Receipt.Version {
					t.Fatalf("current moved: %+v, %v", state, err)
				}
				report, toRollBack, err := r.d.SettleRun(r.b.Config, &r.bPolicy)
				if err != nil || len(toRollBack) != 0 || !slices.Contains(report.Completed, r.b.Receipt.ReceiptID) {
					t.Fatalf("the pending bundle did not confirm from the live gateway: report=%+v rollback=%+v error=%v", report, toRollBack, err)
				}
				if state, err := r.d.Store.LoadState(); err != nil || state.Current == nil || state.Current.Version != r.b.Receipt.Version {
					t.Fatalf("current after settle: %+v, %v", state, err)
				}
			})
		}
	}
}

// Another signed bundle C can render the bytes a pending receipt B committed
// (a version bump that changed no setting). The delivery being installed
// owns those bytes, also in the installer child process, which does not
// know it (no CurrentReceiptID) and also while the generation record names
// the pending B: C can take over during the outage (GAP-1187).
func TestDriverGenerationOwnerOfBytesTwoBundlesRender(t *testing.T) {
	r := newPendingRun(t, enterprisebundle.StateStaged)
	bump := r.f.variant(t, settingsOnly(t, "action"), func(in *enterprisebundle.ComposeInput) { in.Version, in.ChangeSummary = 7, "bump" })
	c, err := r.d.Prepare(t.Context(), bump, nil)
	if err != nil || c.Receipt == nil || !bytes.Equal(c.Config, r.b.Config) {
		t.Fatalf("setup: %+v, %v", c, err)
	}
	opt, ok, err := r.d.ConfigGenerationOptions(c.Config)
	if err != nil || !ok || opt.Bundle.Version != c.Receipt.Version {
		t.Fatalf("attribution in the installer child with the pending commit recorded = %+v, %v, %v", opt, ok, err)
	}
	if err := os.Remove(configwrite.GenerationPath(r.d.ConfigPath)); err != nil {
		t.Fatal(err)
	}
	if opt, ok, err := r.d.ConfigGenerationOptions(c.Config); err != nil || !ok || opt.Bundle.Version != c.Receipt.Version {
		t.Fatalf("attribution with no record = %+v, %v, %v", opt, ok, err)
	}
	r.d.CurrentReceiptID = c.Receipt.ReceiptID
	if opt, ok, err := r.d.ConfigGenerationOptions(c.Config); err != nil || !ok || opt.Bundle.Version != c.Receipt.Version {
		t.Fatalf("attribution bound to the current delivery = %+v, %v, %v", opt, ok, err)
	}
}

// A pending bundle B whose rendered bytes a higher bundle C committed during
// the outage (GAP-1187) settles superseded once C confirms: B is never
// failed not_confirmed and never named for a rollback, because C's config is
// the installed one (GAP-2088).
func TestDriverPendingBundleWhoseBytesAHigherBundleCommittedIsSuperseded(t *testing.T) {
	for _, pendingState := range []string{enterprisebundle.StateStaged, enterprisebundle.StateApplied} {
		t.Run(pendingState, func(t *testing.T) {
			r := newPendingRun(t, pendingState)
			bump := r.f.variant(t, settingsOnly(t, "action"), func(in *enterprisebundle.ComposeInput) { in.Version, in.ChangeSummary = 7, "bump" })
			c, err := r.d.Prepare(t.Context(), bump, nil)
			if err != nil || c.Receipt == nil || !bytes.Equal(c.Config, r.b.Config) {
				t.Fatalf("setup: %+v, %v", c, err)
			}
			// C committed the bytes and its run was killed; the gateway is back.
			cPolicy := installPreparedBundle(t, r.d, c)
			report, toRollBack, err := r.d.SettleRun(c.Config, &cPolicy)
			if err != nil || len(toRollBack) != 0 || !slices.Contains(report.Completed, c.Receipt.ReceiptID) {
				t.Fatalf("settle: report=%+v rollback=%+v error=%v", report, toRollBack, err)
			}
			receipts, err := r.d.Store.Receipts()
			if err != nil {
				t.Fatal(err)
			}
			var b *enterprisebundle.Receipt
			for _, rc := range receipts {
				if rc.ReceiptID == r.b.Receipt.ReceiptID {
					b = rc
				}
			}
			if b == nil || b.State != enterprisebundle.StateFailed || b.ErrorCode != enterprisebundle.CodeSuperseded || b.RolledBack ||
				!strings.Contains(b.ErrorMessage, "version 7") || !strings.Contains(b.ErrorMessage, "nothing was rolled back") {
				t.Fatalf("B after C took its bytes over = %+v", b)
			}
			if slices.Contains(report.Pending, b.ReceiptID) || slices.Contains(report.Interrupted, b.ReceiptID) {
				t.Fatalf("B reported pending or interrupted: %+v", report)
			}
			if state, err := r.d.Store.LoadState(); err != nil || state.Current == nil || state.Current.Version != c.Receipt.Version {
				t.Fatalf("current after settle: %+v, %v", state, err)
			}
		})
	}
}

// A failed delivery records rolled_back only when the installed config, its
// generation record and the live gateway prove the last good bundle enforces
// again. A transaction that put back an unconfirmed predecessor (a pending
// commit) is reported as that, never as a rollback, and the last good bundle
// is not installed over it.
func TestDriverFailedDeliveryRecordsOnlyAProvenRollback(t *testing.T) {
	for _, tc := range []struct {
		name         string
		pendingState string
		policy       func(r *pendingRun) enterprisebundle.GatewayPolicy
		rolledBack   bool
		// pending: the gateway was down and the run's own base config is
		// installed: the delivery stays open (GAP-0751).
		pending bool
	}{
		{name: "pending applied predecessor put back, gateway unavailable", pendingState: enterprisebundle.StateApplied,
			policy: func(*pendingRun) enterprisebundle.GatewayPolicy { return enterprisebundle.GatewayPolicy{} }},
		{name: "pending applied predecessor put back, gateway enforces it", pendingState: enterprisebundle.StateApplied,
			policy: func(r *pendingRun) enterprisebundle.GatewayPolicy { return r.bPolicy }},
		{name: "pending staged predecessor put back, gateway enforces it", pendingState: enterprisebundle.StateStaged,
			policy: func(r *pendingRun) enterprisebundle.GatewayPolicy { return r.bPolicy }},
		{name: "last good put back, gateway proves it",
			policy: func(r *pendingRun) enterprisebundle.GatewayPolicy { return r.aPolicy }, rolledBack: true},
		{name: "last good put back, gateway unavailable",
			policy: func(*pendingRun) enterprisebundle.GatewayPolicy { return enterprisebundle.GatewayPolicy{} }, pending: true},
		{name: "last good put back, gateway rejected the reload",
			policy: func(r *pendingRun) enterprisebundle.GatewayPolicy {
				p := r.aPolicy
				p.ReloadError = "rule pack"
				return p
			}},
		{name: "last good put back, gateway at another generation",
			policy: func(r *pendingRun) enterprisebundle.GatewayPolicy {
				p := r.aPolicy
				p.Generation++
				return p
			}},
		{name: "last good put back, gateway names another bundle",
			policy: func(r *pendingRun) enterprisebundle.GatewayPolicy {
				p := r.aPolicy
				p.BundleVersion++
				return p
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPendingRun(t, tc.pendingState)
			higher := r.f.variant(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) { in.Version, in.ChangeSummary = 7, "higher" })
			c, err := r.d.Prepare(t.Context(), higher, nil)
			if err != nil || c.Receipt == nil {
				t.Fatalf("a higher version over the pending bundle was refused: %+v, %v", c, err)
			}
			predecessor := r.a
			if r.b != nil {
				predecessor = r.b
			}
			putBack := false
			_, err = r.d.Finish(c, predecessor.ConfigSHA256, []string{"service_start_failed"}, tc.policy(r), false,
				func() (string, bool) { putBack = true; return "", true })
			if tc.pending {
				if enterprisebundle.CodeOf(err) != enterprisebundle.CodeNotConfirmed || enterprisebundle.Finished(c.Receipt.State) || c.Receipt.RolledBack || putBack {
					t.Fatalf("outage: finish = %v, receipt %+v, put back %v; want it pending", err, c.Receipt, putBack)
				}
				return
			}
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeApplyFailed || c.Receipt.State != enterprisebundle.StateFailed {
				t.Fatalf("finish = %v, receipt %+v", err, c.Receipt)
			}
			if putBack || c.Receipt.RolledBack != tc.rolledBack {
				t.Fatalf("rolled_back = %v (put back %v), want %v", c.Receipt.RolledBack, putBack, tc.rolledBack)
			}
			if r.b == nil {
				if c.InstalledPending != nil {
					t.Fatalf("the last good bundle was reported as a pending commit: %+v", c.InstalledPending)
				}
				return
			}
			if c.InstalledPending == nil || c.InstalledPending.ReceiptID != r.b.Receipt.ReceiptID {
				t.Fatalf("the restored predecessor was not reported: %+v", c.InstalledPending)
			}
			if got := r.unsettled(t); got.ReceiptID != r.b.Receipt.ReceiptID || got.State != tc.pendingState {
				t.Fatalf("pending predecessor = %+v", got)
			}
		})
	}
}
