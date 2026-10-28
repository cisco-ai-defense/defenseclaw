// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// fix/r104-windows: the signed-bundle settle is one transaction. A staged
// or applied receipt is confirmed only from the gateway's live report of
// its digest, generation and bundle identity; matching bytes or text never
// prove it; a temporary outage leaves a committed bundle pending instead of
// failing it; and the rollback target is kept until a new apply is proven.

const r104StrippedRefs = "  signature_packs:\n    - discovery/signature-packs/team.json\n  confidence_policy_path: discovery/confidence.yaml\n"

const r104BundleB = "b-01JA0000000000000000000484"

// r104Pair confirms bundle A, then stages bundle B (version A+1) whose
// rendered config is byte-identical to A's, from a run that started with A's
// config installed. comment, when set, is appended to both bundles'
// config.yaml with B's predictable version directory (receipt ID = bundle
// ID) in it: the GAP-0484 text-scan trap.
func r104Pair(t *testing.T, comment bool) (*enterprisebundle.Driver, *enterprisebundle.Prepared, *enterprisebundle.Prepared, enterprisebundle.GatewayPolicy) {
	t.Helper()
	f := newFixture(t, strings.Replace(bundleConfig(t), r104StrippedRefs, "", 1), nil)
	d := driverFor(t, f)
	if comment {
		bDir := enterprisebundle.VersionDirNameForReceipt(f.in.Version+1, r104BundleB, r104BundleB)
		raw := append(append([]byte(nil), f.in.Bundle.Files["config.yaml"]...),
			[]byte("# kept for audit: "+filepath.Join(d.Store.BundlesDir, bDir, "policies")+"\n")...)
		f.in.Bundle.Files["config.yaml"] = raw
		if err := os.WriteFile(filepath.Join(f.in.Root, "config.yaml"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, manifest, err := enterprisebundle.Compose(t.Context(), f.in)
		if err != nil {
			t.Fatal(err)
		}
		f.bundle = f.signed(t, manifest)
	}
	a, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	proofA := installPreparedBundle(t, d, a)
	if _, err := d.Finish(a, a.ConfigSHA256, nil, proofA, false, nil); err != nil {
		t.Fatal(err)
	}
	f.in.Version++
	f.in.BundleID = r104BundleB
	_, manifest, err := enterprisebundle.Compose(t.Context(), f.in)
	if err != nil {
		t.Fatal(err)
	}
	d.EnforcedConfig = a.Config
	b, err := d.Prepare(t.Context(), f.signed(t, manifest), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Config, b.Config) {
		t.Fatal("the regression needs identical rendered configs")
	}
	if b.Receipt.BaseConfigSHA256 != a.ConfigSHA256 {
		t.Fatalf("staged receipt base = %q, want the config the run started from", b.Receipt.BaseConfigSHA256)
	}
	return d, a, b, proofA
}

func r104StateNames(t *testing.T, d *enterprisebundle.Driver, id string) bool {
	t.Helper()
	st, err := d.Store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	return st.Current != nil && st.Current.BundleID == id
}

// GAP-0483: B renders A's config and digest and its run stopped after
// staging, before installing. Whatever the gateway reports, B is never
// confirmed from A's bytes and digest: without B's commit it is interrupted
// and A stays current and the rollback target.
func TestSettleNeverConfirmsAnIdenticalStagedBundleFromMatchingBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy func(a enterprisebundle.GatewayPolicy, b *enterprisebundle.Prepared) *enterprisebundle.GatewayPolicy
	}{
		{name: "gateway names A", policy: func(a enterprisebundle.GatewayPolicy, _ *enterprisebundle.Prepared) *enterprisebundle.GatewayPolicy {
			return &a
		}},
		{name: "gateway claims B without a commit", policy: func(a enterprisebundle.GatewayPolicy, b *enterprisebundle.Prepared) *enterprisebundle.GatewayPolicy {
			a.BundleID, a.BundleVersion = b.Receipt.BundleID, b.Receipt.Version
			return &a
		}},
		{name: "gateway down", policy: func(enterprisebundle.GatewayPolicy, *enterprisebundle.Prepared) *enterprisebundle.GatewayPolicy {
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, a, b, proofA := r104Pair(t, false)
			report, rollback, err := d.SettleRun(a.Config, tc.policy(proofA, b))
			if err != nil {
				t.Fatal(err)
			}
			if len(rollback) != 0 || !slices.Contains(report.Interrupted, b.Receipt.ReceiptID) || slices.Contains(report.Completed, b.Receipt.ReceiptID) {
				t.Fatalf("report %+v, rollback %d", report, len(rollback))
			}
			if rc := receiptOf(t, d, b.Receipt.ReceiptID); rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeInterrupted || rc.ConfigGeneration != 0 {
				t.Fatalf("B = %s %s gen %d", rc.State, rc.ErrorCode, rc.ConfigGeneration)
			}
			if !r104StateNames(t, d, a.Receipt.BundleID) {
				t.Fatal("A is no longer current")
			}
		})
	}
}

// A repeat of the same signed bundle while the first receipt is applied
// can have identical bytes and bundle identity. Its staged receipt did not
// commit the already installed generation and must not become current.
func TestSettleDoesNotBorrowPendingSameBundleCommit(t *testing.T) {
	f := newFixture(t, strings.Replace(bundleConfig(t), r104StrippedRefs, "", 1), nil)
	d := driverFor(t, f)
	first, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof := installPreparedBundle(t, d, first)
	if _, err := d.Finish(first, first.ConfigSHA256, nil, enterprisebundle.GatewayPolicy{}, false, nil); enterprisebundle.CodeOf(err) != enterprisebundle.CodeNotConfirmed {
		t.Fatalf("first receipt did not remain pending: %v", err)
	}
	d.EnforcedConfig = first.Config
	second, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Config, second.Config) || second.Receipt.BaseConfigSHA256 != first.ConfigSHA256 {
		t.Fatal("repeat did not start from identical signed config")
	}
	report, rollback, err := d.SettleRun(first.Config, nil)
	if err != nil || len(rollback) != 0 || !slices.Contains(report.Interrupted, second.Receipt.ReceiptID) ||
		!slices.Contains(report.Pending, first.Receipt.ReceiptID) || slices.Contains(report.Pending, second.Receipt.ReceiptID) {
		t.Fatalf("outage settle: report=%+v rollback=%+v error=%v", report, rollback, err)
	}
	if rc := receiptOf(t, d, second.Receipt.ReceiptID); rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeInterrupted {
		t.Fatalf("uncommitted repeat receipt = %+v", rc)
	}
	report, rollback, err = d.SettleRun(first.Config, &proof)
	if err != nil || len(rollback) != 0 || !slices.Contains(report.Completed, first.Receipt.ReceiptID) ||
		receiptOf(t, d, first.Receipt.ReceiptID).State != enterprisebundle.StateConfirmed {
		t.Fatalf("original receipt was not confirmed: report=%+v rollback=%+v error=%v", report, rollback, err)
	}
}

// GAP-0484: A comment in the installed config that names B's version
// directory is not evidence that B's transaction installed anything. With
// the base record (and, for a legacy receipt, the value-only scan) B is
// interrupted and A stays the last good config: no rollback target is
// discarded.
func TestSettleIgnoresACommentNamingTheStagedVersionDirectory(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "base record", true: "legacy receipt"}[legacy], func(t *testing.T) {
			d, a, b, _ := r104Pair(t, true)
			if !slices.Contains(enterprisebundle.VersionDirsNamed(a.Config, d.Store.BundlesDir), b.Receipt.Dir) {
				t.Fatalf("the trap needs the comment to name B's directory %s", b.Receipt.Dir)
			}
			if got := enterprisebundle.VersionDirsInValues(a.Config, d.Store.BundlesDir); slices.Contains(got, b.Receipt.Dir) {
				t.Fatalf("the value scan read the comment: %v", got)
			}
			if legacy {
				r104DropBaseRecord(t, d, b.Receipt.ReceiptID)
			}
			// The gateway is down: GAP-0484's scenario.
			report, rollback, err := d.SettleRun(a.Config, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(rollback) != 0 || !slices.Contains(report.Interrupted, b.Receipt.ReceiptID) {
				t.Fatalf("a comment made B a rollback target: report %+v, rollback %d", report, len(rollback))
			}
			if !r104StateNames(t, d, a.Receipt.BundleID) {
				t.Fatal("A is no longer current")
			}
		})
	}
}

// The base record also proves the opposite: a run whose transaction wrote
// B's bytes over a different config without committing them installed B
// unconfirmed, so B fails and is named for the rollback, even when B's
// config names no version directory of its own.
func TestSettleNamesAnUncommittedInstallOverAnotherBaseForRollback(t *testing.T) {
	f := newFixture(t, strings.Replace(bundleConfig(t), r104StrippedRefs, "", 1), nil)
	d := driverFor(t, f)
	d.EnforcedConfig = []byte("config_version: 9\n")
	b, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.ConfigPath, b.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	report, rollback, err := d.SettleRun(b.Config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollback) != 1 || rollback[0].ReceiptID != b.Receipt.ReceiptID || len(report.Interrupted) != 0 || len(report.Pending) != 0 {
		t.Fatalf("report %+v, rollback %d", report, len(rollback))
	}
	if rc := receiptOf(t, d, b.Receipt.ReceiptID); rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeNotConfirmed {
		t.Fatalf("B = %s %s", rc.State, rc.ErrorCode)
	}
}

// GAP-0485 and the outage rule, at every step boundary of a settle of B,
// whose transaction committed B's config:
//   - stopped before Finish (staged), gateway down / not ready: pending;
//   - stopped after Advance(applied), before Confirm, gateway down: pending;
//   - gateway up with another identity or digest: failed, rollback;
//   - gateway proves B: confirmed;
//   - Confirm wrote bundle-state.json naming B but sealing it failed: the
//     settle returns the error, B stays applied, and the next settle
//     completes it from the state even with the gateway down.
func TestSettleRunStepBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		applied bool
		policy  func(proof enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy
		want    string // pending, confirmed, rollback
	}{
		{name: "staged, gateway down", policy: func(enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return nil }, want: "pending"},
		{name: "staged, gateway not ready", policy: func(enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy {
			return &enterprisebundle.GatewayPolicy{}
		}, want: "pending"},
		{name: "applied, gateway down", applied: true, policy: func(enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return nil }, want: "pending"},
		{name: "staged, gateway names another bundle", policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy {
			p.BundleID = "b-01JA0000000000000000000099"
			return &p
		}, want: "rollback"},
		{name: "applied, gateway reports another digest", applied: true, policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy {
			p.Digest = gatewayDigest
			return &p
		}, want: "rollback"},
		{name: "applied, gateway rejected the reload", applied: true, policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy {
			p.Applied, p.ReloadError, p.Digest = false, "invalid", ""
			return &p
		}, want: "rollback"},
		{name: "staged, gateway proves it", policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return &p }, want: "confirmed"},
		{name: "applied, gateway proves it", applied: true, policy: func(p enterprisebundle.GatewayPolicy) *enterprisebundle.GatewayPolicy { return &p }, want: "confirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), nil)
			d := driverFor(t, f)
			b, err := d.Prepare(t.Context(), f.bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			proof := installPreparedBundle(t, d, b)
			if tc.applied {
				if err := d.Store.Advance(b.Receipt, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
					rc.EffectivePolicyDigest, rc.ConfigGeneration = proof.EffectiveDigest, proof.Generation
				}); err != nil {
					t.Fatal(err)
				}
			}
			report, rollback, err := d.SettleRun(b.Config, tc.policy(proof))
			if err != nil {
				t.Fatal(err)
			}
			rc := receiptOf(t, d, b.Receipt.ReceiptID)
			switch tc.want {
			case "pending":
				if !slices.Contains(report.Pending, rc.ReceiptID) || len(rollback) != 0 || enterprisebundle.Finished(rc.State) {
					t.Fatalf("an outage settled a committed bundle: report %+v, rollback %d, receipt %s", report, len(rollback), rc.State)
				}
				// The retry once the gateway runs confirms it.
				if _, _, err := d.SettleRun(b.Config, &proof); err != nil {
					t.Fatal(err)
				}
				if rc := receiptOf(t, d, b.Receipt.ReceiptID); rc.State != enterprisebundle.StateConfirmed || !r104StateNames(t, d, rc.BundleID) {
					t.Fatalf("the retry did not confirm the pending bundle: %s", rc.State)
				}
			case "confirmed":
				if rc.State != enterprisebundle.StateConfirmed || len(rollback) != 0 || !r104StateNames(t, d, rc.BundleID) {
					t.Fatalf("receipt %s, rollback %d", rc.State, len(rollback))
				}
			case "rollback":
				if !enterprisebundle.Finished(rc.State) || rc.State == enterprisebundle.StateConfirmed || len(rollback) != 1 || len(report.Pending) != 0 {
					t.Fatalf("receipt %s, rollback %d, report %+v", rc.State, len(rollback), report)
				}
			}
		})
	}
}

// GAP-0485: Confirm durably wrote bundle-state.json naming the proven B,
// then sealing that file failed. The settle reports the error and leaves B
// applied, never failed and never a rollback target; the next settle
// completes it from the state ref, with the gateway down.
func TestSettleKeepsAProvenBundleWhenItsStatePublicationFails(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	b, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof := installPreparedBundle(t, d, b)
	d.Store.PublishPrivateFile = func(path string) error {
		if path == d.Store.StatePath() {
			return errors.New("set the access control list: access denied")
		}
		return nil
	}
	report, rollback, err := d.SettleRun(b.Config, &proof)
	if err == nil || len(rollback) != 0 || slices.Contains(report.Completed, b.Receipt.ReceiptID) {
		t.Fatalf("settle = %+v, rollback %d, err %v", report, len(rollback), err)
	}
	if rc := receiptOf(t, d, b.Receipt.ReceiptID); rc.State != enterprisebundle.StateApplied || rc.ErrorCode != "" {
		t.Fatalf("a publication error failed the proven receipt: %s %s", rc.State, rc.ErrorCode)
	}
	if !r104StateNames(t, d, b.Receipt.BundleID) {
		t.Fatal("the state write the cut kept does not name B")
	}
	d.Store.PublishPrivateFile = nil
	report, rollback, err = d.SettleRun(b.Config, nil)
	if err != nil || len(rollback) != 0 || !slices.Contains(report.Completed, b.Receipt.ReceiptID) {
		t.Fatalf("recovery = %+v, rollback %d, err %v", report, len(rollback), err)
	}
	if rc := receiptOf(t, d, b.Receipt.ReceiptID); rc.State != enterprisebundle.StateConfirmed {
		t.Fatalf("recovered receipt = %s", rc.State)
	}
}

// Finish has the same rule: a Confirm error after the proof keeps the
// receipt applied, returns a state_invalid error that names the next step,
// and never runs the rollback.
func TestFinishKeepsAProvenBundleWhenConfirmFails(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	b, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof := installPreparedBundle(t, d, b)
	d.Store.PublishPrivateFile = func(path string) error {
		if path == d.Store.StatePath() {
			return errors.New("access denied")
		}
		return nil
	}
	rolledBack := false
	_, err = d.Finish(b, b.ConfigSHA256, nil, proof, false, func() (string, bool) { rolledBack = true; return "", true })
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeStateInvalid || !strings.Contains(err.Error(), "enterprise windows ensure") || rolledBack {
		t.Fatalf("finish = %v, rolled back %v", err, rolledBack)
	}
	if rc := receiptOf(t, d, b.Receipt.ReceiptID); rc.State != enterprisebundle.StateApplied {
		t.Fatalf("receipt = %s", rc.State)
	}
}

func TestVersionDirsInValuesReadsOnlyValues(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundles")
	name := enterprisebundle.VersionDirName(3, "b-01JA0000000000000000000003")
	path := filepath.Join(dir, name, "rules")
	raw := []byte("# " + path + "\n" + "guardrail:\n  rules_dir: " + path + "\n")
	if got := enterprisebundle.VersionDirsInValues(raw, dir); len(got) != 1 || got[0] != name {
		t.Fatalf("value = %v", got)
	}
	if got := enterprisebundle.VersionDirsInValues([]byte("# "+path+"\nguardrail: {}\n"), dir); len(got) != 0 {
		t.Fatalf("comment = %v", got)
	}
	if got := enterprisebundle.VersionDirsInValues([]byte(":\t:bad"), dir); got != nil {
		t.Fatalf("unparsable = %v", got)
	}
}

// r104DropBaseRecord rewrites the stored receipt as a 1.0.3 run wrote it:
// without base_config_sha256.
func r104DropBaseRecord(t *testing.T, d *enterprisebundle.Driver, id string) {
	t.Helper()
	path := filepath.Join(d.Store.LifecycleDir, enterprisebundle.ReceiptsDirName, id+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["base_config_sha256"]; !ok {
		t.Fatal("receipt has no base record to drop")
	}
	delete(doc, "base_config_sha256")
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
