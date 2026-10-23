// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
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
		Store: store, ConfigPath: filepath.Join(root, "etc", "config.yaml"), AnchorsPath: anchorsPath, AnchorTrust: func(string) error { return nil },
		Platform: runtime.GOOS, ProductVersion: "1.0.2", Now: func() time.Time { return verifyAt }, Digester: digester,
	}
}

func enforcing(digest string) enterprisebundle.GatewayPolicy {
	return enterprisebundle.GatewayPolicy{EffectiveDigest: digest, Digest: digest, Generation: 4, Applied: true}
}

// installPreparedBundle models the lifecycle commit, including its durable
// signed-bundle attribution, before the gateway adopts that generation.
func installPreparedBundle(t *testing.T, d *enterprisebundle.Driver, p *enterprisebundle.Prepared) enterprisebundle.GatewayPolicy {
	t.Helper()
	opt, ok := enterprisebundle.GenerationOptions(p.Receipt)
	if !ok {
		t.Fatal("bundle receipt has no principal")
	}
	result, err := configwrite.Locked(t.Context(), d.ConfigPath, opt, func() (bool, error) {
		return true, os.WriteFile(d.ConfigPath, p.Config, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := enforcing(p.Receipt.ExpectedDigest)
	policy.Generation = result.Generation
	policy.BundleID, policy.BundleVersion = p.Receipt.BundleID, p.Receipt.Version
	return policy
}

func TestDriverInterruptedIdenticalConfigKeepsConfirmedBundle(t *testing.T) {
	settings := strings.Replace(bundleConfig(t), "  signature_packs:\n    - discovery/signature-packs/team.json\n  confidence_policy_path: discovery/confidence.yaml\n", "", 1)
	f := newFixture(t, settings, nil)
	d := driverFor(t, f)
	current, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := installPreparedBundle(t, d, current)
	if _, err := d.Finish(current, current.ConfigSHA256, nil, policy, false, nil); err != nil {
		t.Fatal(err)
	}
	f.in.Version++
	f.in.BundleID = "b-01JA0000000000000000000042"
	_, raw, err := enterprisebundle.Compose(t.Context(), f.in)
	if err != nil {
		t.Fatal(err)
	}
	// The run that staged B started from A's installed config.
	d.EnforcedConfig = current.Config
	staged, err := d.Prepare(t.Context(), f.signed(t, raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.Config, staged.Config) {
		t.Fatal("regression requires identical rendered configs")
	}
	report, rollback, err := d.SettleRun(current.Config, &policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollback) != 0 || len(report.Interrupted) != 1 || report.Interrupted[0] != staged.Receipt.ReceiptID {
		t.Fatalf("an identical config the confirmed bundle committed was named for a rollback: report %+v, rollback %v", report, rollback)
	}
	state, err := d.Store.LoadState()
	if err != nil || state.Current == nil || state.Current.BundleID != current.Receipt.BundleID || state.Floor != current.Receipt.Version {
		t.Fatalf("an interrupted delivery replaced the applied bundle: %+v, %v", state, err)
	}
	receipts, err := d.Store.Receipts()
	if err != nil || len(receipts) == 0 || receipts[0].State != enterprisebundle.StateFailed || receipts[0].ConfigGeneration != 0 {
		t.Fatalf("unapplied receipt borrowed the installed generation: %+v, %v", receipts, err)
	}
	// A retry can recover after a real lifecycle commit even though its
	// bytes are identical: the generation and the gateway now identify B.
	retry, err := d.Prepare(t.Context(), f.signed(t, raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	policy = installPreparedBundle(t, d, retry)
	if _, _, err := d.SettleRun(retry.Config, &policy); err != nil {
		t.Fatal(err)
	}
	state, err = d.Store.LoadState()
	if err != nil || state.Current == nil || state.Current.BundleID != retry.Receipt.BundleID || state.Floor != retry.Receipt.Version {
		t.Fatalf("proven retry was not confirmed: %+v, %v", state, err)
	}
}

func TestDriverStageDiskFullKeepsAClassifiedReceipt(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	d.Store.EnsureStageDirectory = func(_, path string) error {
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOSPC}
	}
	p, err := d.Prepare(t.Context(), f.bundle, nil)
	if enterprisebundle.CodeOf(err) != enterprisebundle.Code("disk_full") || p == nil || p.Receipt == nil {
		t.Fatalf("stage error = %+v, %v; want disk_full receipt", p, err)
	}
	receipts, err := d.Store.Receipts()
	if err != nil || len(receipts) != 1 || receipts[0].State != enterprisebundle.StateFailed ||
		receipts[0].ErrorCode != enterprisebundle.Code("disk_full") {
		t.Fatalf("persisted receipts = %+v, %v; want failed disk_full", receipts, err)
	}
	if runtime.GOOS == "windows" {
		// Native Windows writes report ERROR_DISK_FULL (112), not ENOSPC.
		if got := enterprisebundle.CodeOf(enterprisebundle.StageError(syscall.Errno(112))); got != enterprisebundle.Code("disk_full") {
			t.Fatalf("Windows disk-full code = %s", got)
		}
	}
}

func TestDriverConfirmedRollbackRecordsSignedProvenance(t *testing.T) {
	const earlier = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z29"
	f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) {
		in.RollbackOf = earlier
	})
	d := driverFor(t, f)
	p, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Receipt.RollbackOf != earlier {
		t.Fatalf("verified receipt rollback_of = %q", p.Receipt.RollbackOf)
	}
	if _, err := d.Finish(p, p.ConfigSHA256, nil, installPreparedBundle(t, d, p), false, nil); err != nil {
		t.Fatal(err)
	}
	last, _, err := d.Store.Latest()
	if err != nil || last == nil || last.RollbackOf != earlier {
		t.Fatalf("stored receipt = %+v, %v", last, err)
	}
	raw, err := os.ReadFile(d.Store.PublicReceiptPath())
	if err != nil {
		t.Fatal(err)
	}
	var public struct {
		RollbackOf string `json:"rollback_of"`
	}
	if err := json.Unmarshal(raw, &public); err != nil || public.RollbackOf != earlier {
		t.Fatalf("public receipt rollback_of = %q, %v", public.RollbackOf, err)
	}
}

func TestDriverRefusesDeviceKeyMoveBeforePromotion(t *testing.T) {
	for _, platform := range enterprisebundle.Platforms {
		t.Run(platform, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) { in.HostPlatform = platform })
			d := driverFor(t, f)
			d.Platform = platform
			d.EnforcedConfig = []byte("gateway:\n  device_key_file: /old/device.key\n")
			p, err := d.Prepare(t.Context(), f.bundle, nil)
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeInvalidArguments || p == nil || p.Receipt.State != enterprisebundle.StateFailed {
				t.Fatalf("Prepare = %+v, %v", p, err)
			}
			version := d.Store.VersionDir(enterprisebundle.VersionDirNameForReceipt(p.Receipt.Version, p.Receipt.BundleID, p.Receipt.ReceiptID))
			if _, err := os.Stat(version); !os.IsNotExist(err) {
				t.Fatalf("bundle promoted before refusal: %v", err)
			}
		})
	}
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
					version := d.Store.VersionDir(enterprisebundle.VersionDirNameForReceipt(p.Receipt.Version, p.Receipt.BundleID, p.Receipt.ReceiptID))
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
			{name: "non-comparable equal digest"},
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
				policy := installPreparedBundle(t, d, p)
				policy.Digest, policy.EffectiveDigest = digest, digest
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
				if !tc.comparable && !containsWarning(p.Receipt.Status(state.Current).WarningCodes, enterprisebundle.WarnDigestUnverifiable) {
					t.Fatal("confirmed bundle status omitted digest_unverifiable")
				}
			})
		}
	}
}

// GAP-0113: the refusal holds for every signer and device platform pair, a
// cross-host signer included.
func TestDriverRefusesComparableDigestBeforeActivation(t *testing.T) {
	for _, pair := range platformPairs() {
		signer, platform := pair[0], pair[1]
		t.Run(signer+"-signs-"+platform, func(t *testing.T) {
			f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) { in.HostPlatform = signer })
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
			version := d.Store.VersionDir(enterprisebundle.VersionDirNameForReceipt(manifest.Version, manifest.BundleID, prepared.Receipt.ReceiptID))
			if _, err := os.Stat(version); !os.IsNotExist(err) {
				t.Fatalf("mismatched version was promoted: %v", err)
			}
		})
	}
}

// platformPairs is every signer and device platform pair.
func platformPairs() [][2]string {
	var pairs [][2]string
	for _, signer := range enterprisebundle.Platforms {
		for _, device := range enterprisebundle.Platforms {
			pairs = append(pairs, [2]string{signer, device})
		}
	}
	return pairs
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
	st, err := d.Finish(good, good.ConfigSHA256, nil, installPreparedBundle(t, d, good), true, rollback)
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
	// Setup CONFIG= restoring these same signed bytes must retain the
	// confirmed principal even after the delivery receipts are pruned.
	if err := os.Remove(filepath.Join(d.Store.LifecycleDir, enterprisebundle.ReceiptsDirName, good.Receipt.ReceiptID+".json")); err != nil {
		t.Fatal(err)
	}
	d.RefuseRestart = func(_, _ []byte) string { return "the confirmed config restores a restart setting" }
	deferred, deferErr := d.Prepare(ctx, f.bundle, nil)
	if enterprisebundle.CodeOf(deferErr) != enterprisebundle.CodeRestartDeferred || deferred.Receipt.State != enterprisebundle.StateFailed {
		t.Fatalf("repeated restart delivery was not deferred: %+v, %v", deferred, deferErr)
	}
	d.RefuseRestart = nil
	opt, recorded, generationErr := d.ConfigGenerationOptions(good.Config)
	if generationErr != nil || !recorded || opt.Actor != good.Receipt.Principal || opt.Bundle.ID != good.Receipt.BundleID {
		t.Fatalf("confirmed config attribution = %+v, %v, %v", opt, recorded, generationErr)
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
		staged        bool
		markedCurrent bool
		// uncommitted: the installed bytes equal the staged bundle's config,
		// which names no version directory of its own, but no lifecycle
		// commit of that bundle recorded them: "config" is a non-bundle
		// lifecycle generation (a CONFIG install), "none" no generation
		// record, "other" a generation of another bundle.
		uncommitted string
	}{
		{name: "enforced", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}, holds: true, confirm: true},
		{name: "gateway enforces another policy", policy: &enterprisebundle.GatewayPolicy{Digest: "sha256:" + fmt.Sprintf("%064d", 2), Applied: true}, holds: true, rollback: true},
		{name: "config rolled back", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}},
		{name: "committed, run stopped before finish", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}, holds: true, staged: true, confirm: true},
		{name: "committed, gateway does not enforce it", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest}, holds: true, staged: true, rollback: true},
		{name: "state marker without this receipt's proof, no live confirmation", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest}, holds: true, markedCurrent: true, rollback: true},
		{name: "state marker without this receipt's proof, live confirmation", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}, holds: true, markedCurrent: true, confirm: true},
		{name: "identical config bytes, config install generation", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}, holds: true, staged: true, uncommitted: "config"},
		{name: "identical config bytes, gateway does not enforce", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest}, holds: true, staged: true, uncommitted: "config"},
		{name: "identical config bytes, no generation record", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}, holds: true, staged: true, uncommitted: "none"},
		{name: "identical config bytes, another bundle's generation", policy: &enterprisebundle.GatewayPolicy{Digest: gatewayDigest, Applied: true}, holds: true, staged: true, uncommitted: "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := bundleConfig(t)
			if tc.uncommitted != "" {
				settings = strings.Replace(settings, "  signature_packs:\n    - discovery/signature-packs/team.json\n  confidence_policy_path: discovery/confidence.yaml\n", "", 1)
			}
			f := newFixture(t, settings, nil)
			d := driverFor(t, f)
			if tc.uncommitted != "" {
				// The identical bytes were installed before the run: it
				// started from them (the receipt's base record).
				base, err := enterprisebundle.RenderConfig(f.bundle, d.Store.VersionDir("unused"))
				if err != nil {
					t.Fatal(err)
				}
				d.EnforcedConfig = base
			}
			p, err := d.Prepare(ctx, f.bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.uncommitted != "" && len(enterprisebundle.VersionDirsNamed(p.Config, d.Store.BundlesDir)) != 0 {
				t.Fatal("identical-bytes case requires a config that names no version directory")
			}
			var committed enterprisebundle.GatewayPolicy
			switch tc.uncommitted {
			case "":
				committed = installPreparedBundle(t, d, p)
			case "none":
				if err := os.WriteFile(d.ConfigPath, p.Config, 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				opt := configwrite.Options{Actor: configwrite.ActorLifecycle, Lifecycle: true}
				if tc.uncommitted == "other" {
					opt = configwrite.Options{Actor: p.Receipt.Principal, Lifecycle: true,
						Bundle: configwrite.BundleRef{ID: "b-01JA0000000000000000000099", Version: p.Receipt.Version + 1, SignerKeyID: p.Receipt.SignerKeyID}}
				}
				result, err := configwrite.Locked(ctx, d.ConfigPath, opt, func() (bool, error) {
					return true, os.WriteFile(d.ConfigPath, p.Config, 0o600)
				})
				if err != nil {
					t.Fatal(err)
				}
				committed.Generation = result.Generation
			}
			policy := *tc.policy
			policy.Generation, policy.BundleID, policy.BundleVersion = committed.Generation, committed.BundleID, committed.BundleVersion
			policy.EffectiveDigest = p.Receipt.ExpectedDigest
			if policy.Digest == gatewayDigest {
				policy.Digest = p.Receipt.ExpectedDigest
			}
			if !tc.staged {
				if err := d.Store.Advance(p.Receipt, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
					rc.EffectivePolicyDigest, rc.ConfigSHA256, rc.ConfigGeneration = p.Receipt.ExpectedDigest, p.ConfigSHA256, committed.Generation
				}); err != nil {
					t.Fatal(err)
				}
			}
			installed := []byte("config_version: 9\n")
			if tc.holds {
				installed = p.Config
			}
			if tc.markedCurrent {
				rc := p.Receipt
				state := enterprisebundle.State{SchemaVersion: enterprisebundle.StateSchemaVersion, Floor: rc.Version,
					Current: &enterprisebundle.Ref{BundleID: rc.BundleID, Version: rc.Version, ManifestSHA256: rc.ManifestSHA256, Dir: rc.Dir}}
				raw, err := json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(d.Store.StatePath(), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			report, rollback, err := d.SettleRun(installed, &policy)
			if err != nil {
				t.Fatal(err)
			}
			st, _ := d.Store.LoadState()
			receipts, err := d.Store.Receipts()
			if err != nil || len(receipts) != 1 {
				t.Fatalf("receipts = %+v, %v", receipts, err)
			}
			if confirmed := receipts[0].State == enterprisebundle.StateConfirmed; confirmed != tc.confirm {
				t.Fatalf("confirmed = %v (report %+v)", confirmed, report)
			}
			if tc.confirm && (st.Current == nil || st.Current.BundleID != p.Receipt.BundleID) {
				t.Fatalf("confirmed receipt has no matching current bundle: %+v", st)
			}
			if (len(rollback) == 1) != tc.rollback {
				t.Fatalf("rollback = %v", rollback)
			}
			if tc.staged && tc.uncommitted == "" && len(report.Interrupted) != 0 {
				t.Fatalf("a committed bundle config was reported as never applied: %+v", report)
			}
			// Matching bytes without the bundle's commit: the run that staged
			// it never installed anything, so the installed config stays the
			// last good one (no rollback target to discard).
			if tc.uncommitted != "" && (len(report.Interrupted) != 1 || report.Interrupted[0] != p.Receipt.ReceiptID ||
				receipts[0].State != enterprisebundle.StateFailed || string(receipts[0].ErrorCode) != string(enterprisebundle.CodeInterrupted)) {
				t.Fatalf("an uncommitted identical-config receipt was not settled as interrupted: report %+v, receipt %+v", report, receipts[0])
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
	retry, err := d.Prepare(context.Background(), f.bundle, nil)
	if err != nil || retry.Receipt.Dir == first.Receipt.Dir {
		t.Fatalf("retry needs a fresh version directory: %v, %+v", err, retry.Receipt)
	}
	after, err := os.ReadFile(filepath.Join(versionDir, enterprisebundle.ManifestName))
	if err != nil || string(after) != string(before) {
		t.Fatalf("installed version directory changed: %v", err)
	}
}

func TestRetryCrashWindowsKeepInstalledConfigFilesComplete(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	first, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	switchConfig := func(raw []byte) {
		t.Helper()
		if err := configwrite.WriteFileDurable(configPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	assertInstalled := func(wantDir string) {
		t.Helper()
		raw, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		dirs := enterprisebundle.VersionDirsNamed(raw, d.Store.BundlesDir)
		if len(dirs) != 1 || dirs[0] != wantDir {
			t.Fatalf("installed config names %v, want %s", dirs, wantDir)
		}
		bundle, err := enterprisebundle.ReadDir(d.Store.VersionDir(dirs[0]))
		if err != nil || len(bundle.Files) != len(f.bundle.Files) {
			t.Fatalf("installed config points at incomplete bundle: %v, files=%d", err, len(bundle.Files))
		}
	}
	switchConfig(first.Config)
	assertInstalled(first.Receipt.Dir)
	// Crash after the next delivery is staged, before promotion.
	staged, err := d.Store.Receive(first.Receipt.BundleID, first.Receipt.Version, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Stage(staged, f.bundle); err != nil {
		t.Fatal(err)
	}
	assertInstalled(first.Receipt.Dir)
	// Crash after a retry promotes its own tree, before config commit.
	retry, err := d.Prepare(t.Context(), f.bundle, nil)
	if err != nil || retry.Receipt.Dir == first.Receipt.Dir {
		t.Fatalf("retry promotion = %+v, %v", retry, err)
	}
	assertInstalled(first.Receipt.Dir)
	// Crash after the atomic config switch, before confirmation.
	switchConfig(retry.Config)
	assertInstalled(retry.Receipt.Dir)
	if _, err := os.Stat(d.Store.VersionDir(first.Receipt.Dir)); err != nil {
		t.Fatalf("old installed directory removed before confirmation: %v", err)
	}
	if err := d.Store.Advance(retry.Receipt, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) {
		r.EffectivePolicyDigest = r.ExpectedDigest
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Confirm(retry.Receipt); err != nil {
		t.Fatal(err)
	}
	assertInstalled(retry.Receipt.Dir)
	if _, err := os.Stat(d.Store.VersionDir(first.Receipt.Dir)); !os.IsNotExist(err) {
		t.Fatalf("superseded directory was not collected after confirmation: %v", err)
	}
}

// F10: Driver.DeliveryID (Windows `bundle apply --delivery-id`) is recorded
// on the receipt Prepare starts, and the result bundle block names it.
func TestDriverRecordsDeliveryID(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	d := driverFor(t, f)
	d.DeliveryID = "agent-7:d.0042"
	p, err := d.Prepare(context.Background(), f.bundle, nil)
	if err != nil || p == nil || p.Receipt == nil {
		t.Fatalf("prepare = %+v, %v", p, err)
	}
	if p.Receipt.DeliveryID != d.DeliveryID || p.Receipt.Status(nil).DeliveryID != d.DeliveryID {
		t.Fatalf("receipt delivery id = %q", p.Receipt.DeliveryID)
	}
}
