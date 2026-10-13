// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// driverFor is a Driver over a temp store whose anchor file trusts f.key.
func driverFor(t *testing.T, f *fixture) *enterprisebundle.Driver {
	t.Helper()
	root := t.TempDir()
	// Version directories are read-only; open them up before TempDir removes them.
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	spki, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	anchorsPath := filepath.Join(root, "etc", "trust", enterprisebundle.AnchorsName)
	if err := os.MkdirAll(filepath.Dir(anchorsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf(`{"schema_version":1,"tenant_id":"acme","device_groups":["eng"],"min_version":0,"keys":[{"key_id":"k1","alg":"ed25519","public_key":%q,"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","status":"active"}]}`,
		base64.StdEncoding.EncodeToString(spki))
	if err := os.WriteFile(anchorsPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	store := enterprisebundle.NewStore(filepath.Join(root, "etc", enterprisebundle.BundlesDirName), filepath.Join(root, "lifecycle"))
	store.Now = func() time.Time { return verifyAt }
	return &enterprisebundle.Driver{
		Store: store, AnchorsPath: anchorsPath, AnchorTrust: func(string) error { return nil },
		Platform: runtime.GOOS, ProductVersion: "1.0.2", Now: func() time.Time { return verifyAt }, Digester: digester,
	}
}

func enforcing(digest string) enterprisebundle.GatewayPolicy {
	return enterprisebundle.GatewayPolicy{EffectiveDigest: digest, Digest: digest, Generation: 4, Applied: true}
}

const gatewayDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func TestDriverBundleCapabilityLoss(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, platform := range []string{enterprisebundle.PlatformLinux, enterprisebundle.PlatformDarwin, enterprisebundle.PlatformWindows} {
			t.Run(fmt.Sprintf("%s/strict=%t", platform, strict), func(t *testing.T) {
				f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) { in.HostPlatform = platform })
				d := driverFor(t, f)
				d.Platform = platform
				d.EnforcedConfig = []byte("config_version: 9\nenterprise:\n  openshell: {driver: vm}\nopenshell: {enabled: true}\n")
				d.RefuseCapabilityLoss = strict
				p, err := d.Prepare(context.Background(), f.bundle, nil)
				if p == nil || p.Receipt == nil || !slices.Contains(p.Receipt.DisabledByBundle, "sandbox") || !slices.Contains(p.Receipt.WarningCodes, "capability_disabled") {
					t.Fatalf("receipt = %+v", p)
				}
				if strict {
					if enterprisebundle.CodeOf(err) != enterprisebundle.CodeCapabilityLoss || p.Receipt.State != enterprisebundle.StateFailed {
						t.Fatalf("strict prepare = %+v, %v", p.Receipt, err)
					}
					state, stateErr := d.Store.LoadState()
					if stateErr != nil || state.Current != nil {
						t.Fatalf("strict changed current state: %+v, %v", state, stateErr)
					}
					version := d.Store.VersionDir(enterprisebundle.VersionDirName(p.Receipt.Version, p.Receipt.BundleID))
					if _, statErr := os.Stat(version); !os.IsNotExist(statErr) {
						t.Fatalf("strict promoted a version: %v", statErr)
					}
				} else if err != nil || !slices.ContainsFunc(p.Warnings, func(w enterprisebundle.Warning) bool { return w.Code == "capability_disabled" }) {
					t.Fatalf("permissive prepare = %+v, %v", p.Warnings, err)
				}
			})
		}
	}
}

func TestDriverConfirmationChecksSignedDigestOnAllPlatforms(t *testing.T) {
	for _, platform := range []string{enterprisebundle.PlatformLinux, enterprisebundle.PlatformDarwin, enterprisebundle.PlatformWindows} {
		for _, tc := range []struct {
			name            string
			comparable      bool
			mismatch        bool
			gatewayMismatch bool
			wantCode        enterprisebundle.Code
		}{
			{name: "matching", comparable: true},
			{name: "mismatching comparable", comparable: true, mismatch: true, wantCode: enterprisebundle.CodeDigestMismatch},
			{name: "gateway differs from receipt effective", comparable: true, gatewayMismatch: true, wantCode: enterprisebundle.CodeDigestMismatch},
			{name: "non-comparable", mismatch: true},
		} {
			t.Run(platform+"/"+tc.name, func(t *testing.T) {
				f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) {
					in.HostPlatform = platform
				})
				d := driverFor(t, f)
				d.Platform = platform
				if !tc.comparable {
					d.ProductVersion = "1.0.3"
				}
				p, err := d.Prepare(context.Background(), f.bundle, nil)
				if err != nil {
					t.Fatal(err)
				}
				if p.Receipt.DigestComparable != tc.comparable {
					t.Fatalf("digest comparable = %v", p.Receipt.DigestComparable)
				}
				digest := p.Receipt.ExpectedDigest
				if tc.mismatch {
					digest = gatewayDigest
				}
				policy := enforcing(digest)
				if tc.gatewayMismatch {
					policy.Digest = gatewayDigest
					policy.Applied = false
				}
				rolledBack := false
				state, err := d.Finish(p, p.ConfigSHA256, nil, policy, false, func() (string, bool) {
					rolledBack = true
					return p.Receipt.ExpectedDigest, true
				})
				if got := enterprisebundle.CodeOf(err); got != tc.wantCode {
					t.Fatalf("finish code = %q, want %q: %v", got, tc.wantCode, err)
				}
				if tc.wantCode != "" {
					if !rolledBack || !p.Receipt.RolledBack || p.Receipt.State != enterprisebundle.StateFailed || p.Receipt.ErrorCode != tc.wantCode || state.Current != nil {
						t.Fatalf("mismatch was confirmed or not rolled back: receipt=%+v state=%+v", p.Receipt, state)
					}
					return
				}
				if rolledBack || p.Receipt.State != enterprisebundle.StateConfirmed || state.Current == nil {
					t.Fatalf("matching policy was not confirmed: receipt=%+v state=%+v", p.Receipt, state)
				}
				if !tc.comparable && !containsWarning(p.Receipt.WarningCodes, enterprisebundle.WarnDigestUnverifiable) {
					t.Fatalf("non-comparable digest has no warning: %+v", p.Receipt)
				}
			})
		}
	}
}

func TestDriverRefusesComparableDigestBeforeActivation(t *testing.T) {
	for _, platform := range []string{enterprisebundle.PlatformLinux, enterprisebundle.PlatformDarwin, enterprisebundle.PlatformWindows} {
		t.Run(platform, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) { in.HostPlatform = platform })
			manifest, err := enterprisebundle.DecodeManifest(f.raw)
			if err != nil {
				t.Fatal(err)
			}
			manifest.EffectivePolicy.Digests[platform] = gatewayDigest
			raw, err := manifest.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			d := driverFor(t, f)
			d.Platform = platform
			activated := false
			activate := func(*enterprisebundle.Prepared) { activated = true }
			prepared, err := d.Prepare(t.Context(), f.signed(t, raw), nil)
			if err == nil {
				// This is the caller's activation boundary: it must never run.
				activate(prepared)
			}
			if activated || enterprisebundle.CodeOf(err) != enterprisebundle.CodeDigestMismatch ||
				prepared == nil || prepared.Receipt.State != enterprisebundle.StateFailed {
				t.Fatalf("prepare activated=%v receipt=%+v err=%v", activated, prepared, err)
			}
			version := d.Store.VersionDir(enterprisebundle.VersionDirName(manifest.Version, manifest.BundleID))
			if _, err := os.Stat(version); !os.IsNotExist(err) {
				t.Fatalf("mismatched version was promoted: %v", err)
			}
		})
	}
}

func containsWarning(codes []string, want string) bool {
	for _, code := range codes {
		if code == want {
			return true
		}
	}
	return false
}

// A bundle applied around a transaction the driver does not run becomes
// current only when that transaction installed its config and the gateway
// enforces it; a failed transaction or an unconfirmed policy fails the
// receipt and keeps the last good bundle, and a repeated delivery of the
// current bundle is a no-op that hands back its config.
func TestDriverConfirmsOnlyAnInstalledAndEnforcedBundle(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) { in.Version = 7 })
	d := driverFor(t, f)

	failed, err := d.Prepare(ctx, f.bundle, nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := d.Finish(failed, "", []string{"lifecycle_failed"}, enforcing(gatewayDigest), false, nil); enterprisebundle.CodeOf(err) != enterprisebundle.CodeApplyFailed {
		t.Fatalf("failed transaction: got %v, want apply_failed", err)
	}
	if !failed.Receipt.RolledBack || failed.Receipt.State != enterprisebundle.StateFailed {
		t.Fatalf("failed receipt = %+v", failed.Receipt)
	}

	afterCommit, err := d.Prepare(ctx, f.bundle, nil)
	if err != nil {
		t.Fatalf("prepare after a failed run: %v", err)
	}
	putBack := false
	if _, err := d.Finish(afterCommit, afterCommit.ConfigSHA256, []string{"service_start_failed"}, enforcing(gatewayDigest), false,
		func() (string, bool) { putBack = true; return gatewayDigest, true }); enterprisebundle.CodeOf(err) != enterprisebundle.CodeApplyFailed {
		t.Fatalf("transaction failed after the install: got %v, want apply_failed", err)
	}
	if !putBack || !afterCommit.Receipt.RolledBack {
		t.Fatalf("a transaction that failed after installing the bundle config was not rolled back: %+v", afterCommit.Receipt)
	}

	unconfirmed, err := d.Prepare(ctx, f.bundle, nil)
	if err != nil {
		t.Fatalf("retry prepare: %v", err)
	}
	rolledBack := false
	rollback := func() (string, bool) { rolledBack = true; return gatewayDigest, true }
	if _, err := d.Finish(unconfirmed, unconfirmed.ConfigSHA256, nil, enterprisebundle.GatewayPolicy{Digest: gatewayDigest, ReloadError: "rule pack"}, false, rollback); enterprisebundle.CodeOf(err) != enterprisebundle.CodeNotConfirmed {
		t.Fatalf("rejected reload: got %v, want not_confirmed", err)
	}
	if !rolledBack || !unconfirmed.Receipt.RolledBack || unconfirmed.Receipt.EnforcingDigest != gatewayDigest {
		t.Fatalf("unconfirmed bundle was not rolled back: %+v", unconfirmed.Receipt)
	}
	if st, _ := d.Store.LoadState(); st.Current != nil || st.Floor != 0 {
		t.Fatalf("a failed apply moved the state: %+v", st)
	}

	good, err := d.Prepare(ctx, f.bundle, nil)
	if err != nil {
		t.Fatalf("third prepare: %v", err)
	}
	st, err := d.Finish(good, good.ConfigSHA256, nil, enforcing(good.Receipt.ExpectedDigest), true, rollback)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if st.Current == nil || st.Current.Version != 7 || st.Floor != 7 || !st.Current.RestartRequired || st.Current.EffectivePolicyDigest != good.Receipt.ExpectedDigest {
		t.Fatalf("state after confirm = %+v", st)
	}
	if good.Receipt.State != enterprisebundle.StateConfirmed || !good.Receipt.Restart || !good.Receipt.RestartRequired {
		t.Fatalf("confirmed receipt = %+v", good.Receipt)
	}

	again, err := d.Prepare(ctx, f.bundle, nil)
	if err != nil {
		t.Fatalf("repeat prepare: %v", err)
	}
	if !again.AlreadyApplied || again.Receipt != nil || again.ConfigSHA256 != good.ConfigSHA256 {
		t.Fatalf("repeat delivery = %+v", again)
	}

	tampered := *f.bundle
	tampered.Signature = flip(f.bundle.Signature, len(f.bundle.Signature)/2)
	if p, err := d.Prepare(ctx, &tampered, nil); err == nil || p.Receipt == nil || p.Receipt.State != enterprisebundle.StateFailed {
		t.Fatalf("tampered bundle: prepared %+v, err %v", p, err)
	}
}

// A run that stopped after the receipt reached applied is confirmed on the
// next run only while the deployment holds that config and the gateway
// enforces its digest; otherwise it fails and is named for a rollback.
func TestDriverSettleRunConfirmsOrRollsBackAnAppliedReceipt(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		policy   *enterprisebundle.GatewayPolicy
		holds    bool
		confirm  bool
		rollback bool
		// staged: the transaction committed the config but the run stopped
		// before Finish moved the receipt to applied.
		staged bool
	}{
		{name: "enforced", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}, holds: true, confirm: true},
		{name: "gateway enforces another policy", policy: &enterprisebundle.GatewayPolicy{Digest: "sha256:" + fmt.Sprintf("%064d", 2), Applied: true}, holds: true, rollback: true},
		{name: "config rolled back", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}},
		{name: "committed, run stopped before finish", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}, holds: true, staged: true, confirm: true},
		{name: "committed, gateway does not enforce it", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest}, holds: true, staged: true, rollback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), nil)
			d := driverFor(t, f)
			p, err := d.Prepare(ctx, f.bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			policy := *tc.policy
			policy.EffectiveDigest = p.Receipt.ExpectedDigest
			if policy.Digest == gatewayDigest {
				policy.Digest = p.Receipt.ExpectedDigest
			}
			if !tc.staged {
				if err := d.Store.Advance(p.Receipt, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
					rc.EffectivePolicyDigest, rc.ConfigSHA256 = p.Receipt.ExpectedDigest, p.ConfigSHA256
				}); err != nil {
					t.Fatal(err)
				}
			}
			installed := []byte("config_version: 9\n")
			if tc.holds {
				installed = p.Config
			}
			report, rollback, err := d.SettleRun(installed, &policy)
			if err != nil {
				t.Fatal(err)
			}
			st, _ := d.Store.LoadState()
			if confirmed := st.Current != nil && st.Current.BundleID == p.Receipt.BundleID; confirmed != tc.confirm {
				t.Fatalf("confirmed = %v (report %+v)", confirmed, report)
			}
			if (len(rollback) == 1) != tc.rollback {
				t.Fatalf("rollback = %v", rollback)
			}
			if tc.staged && len(report.Interrupted) != 0 {
				t.Fatalf("a committed bundle config was reported as never applied: %+v", report)
			}
		})
	}
}

func TestDriverSettleRunKeepsInterruptedReceiptOnRetry(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	first, err := d.Prepare(context.Background(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Receipt.State != enterprisebundle.StateStaged {
		t.Fatalf("first receipt state = %s", first.Receipt.State)
	}
	report, rollback, err := d.SettleRun([]byte("config_version: 9\n"), nil)
	if err != nil || len(rollback) != 0 || len(report.Interrupted) != 1 || report.Interrupted[0] != first.Receipt.ReceiptID {
		t.Fatalf("settle = %+v, rollback = %+v, err = %v", report, rollback, err)
	}
	retry, err := d.Prepare(context.Background(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Receipt.ReceiptID == first.Receipt.ReceiptID {
		t.Fatalf("retry reused interrupted receipt %s", retry.Receipt.ReceiptID)
	}
	receipts, err := d.Store.Receipts()
	if err != nil {
		t.Fatal(err)
	}
	var interrupted bool
	for _, rc := range receipts {
		if rc.ReceiptID == first.Receipt.ReceiptID {
			interrupted = rc.State == enterprisebundle.StateFailed && rc.ErrorCode == enterprisebundle.CodeInterrupted
		}
	}
	if !interrupted {
		t.Fatalf("interrupted receipt was lost: %+v", receipts)
	}
}

func TestDriverSettleRunProtectsInstalledUnconfirmedVersion(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	first, err := d.Prepare(context.Background(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	versionDir := d.Store.VersionDir(first.Receipt.Dir)
	before, err := os.ReadFile(filepath.Join(versionDir, enterprisebundle.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	report, rollback, err := d.SettleRun(first.Config, nil)
	if err != nil || len(report.Interrupted) != 0 || len(rollback) != 1 {
		t.Fatalf("settle = %+v, rollback = %+v, err = %v", report, rollback, err)
	}
	if _, err := d.Prepare(context.Background(), f.bundle, nil); err == nil {
		t.Fatal("retry replaced the version directory used by the installed unconfirmed config")
	}
	after, err := os.ReadFile(filepath.Join(versionDir, enterprisebundle.ManifestName))
	if err != nil || string(after) != string(before) {
		t.Fatalf("installed version directory changed: %v", err)
	}
}
