// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0824: the receipt and state keep the digest of the build that
// confirmed the bundle. After an upgrade, status must use this build's
// verified stored bundle and the installed config to check the live policy.
// The historical receipt must remain intact.
func TestBundleStatusAfterProductUpgradeUsesVerifiedCurrentDigest(t *testing.T) {
	for _, sourceVersion := range []string{"1.0.2", "1.0.3"} {
		t.Run(sourceVersion, func(t *testing.T) {
			e := newBundleCLIEnv(t)
			appVersion = sourceVersion
			e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
			signed := filepath.Join(e.dir, "upgrade.dcbundle")
			if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
				t.Fatalf("sign exit %d: %s", code, out)
			}
			b, err := readBundleInput(signed)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := enterprisebundle.DecodeManifest(b.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			// Model the old build's derived digest in the signed manifest as
			// well as its receipt. The upgraded build computes a different one.
			const oldDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			manifest.EffectivePolicy.Digests[runtime.GOOS] = oldDigest
			b.Manifest, err = manifest.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			signature, err := enterprisebundle.Sign(b.Manifest, e.edKey, "k1")
			if err != nil {
				t.Fatal(err)
			}
			b.Signature, err = signature.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			store := bundleDevice(t, e)
			// Production Unix sealing keeps the version directory movable.
			// This status test needs only its signed and hashed contents.
			store.SealVersion = func(string) error { return nil }
			r, err := store.Receive(manifest.BundleID, manifest.Version, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Stage(r, b); err != nil {
				t.Fatal(err)
			}
			manifestHash := sha256.Sum256(b.Manifest)
			if err := store.Advance(r, enterprisebundle.StateVerified, func(rc *enterprisebundle.Receipt) {
				rc.ManifestSHA256 = fmt.Sprintf("%x", manifestHash)
				rc.SignerKeyID, rc.Principal = "k1", manifest.CreatedBy
				rc.ExpectedDigest = manifest.EffectivePolicy.Digests[runtime.GOOS]
				rc.SetDigestComparison(true, false, false)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Promote(r); err != nil {
				t.Fatal(err)
			}
			if err := store.Advance(r, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
				rc.EffectivePolicyDigest, rc.ConfigGeneration = oldDigest, 17
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Confirm(r); err != nil {
				t.Fatal(err)
			}
			root := store.VersionDir(r.Dir)
			layout, err := enterprisebundle.Layout(runtime.GOOS)
			if err != nil {
				t.Fatal(err)
			}
			deviceLayout := enterprisebundle.DeviceLayoutFromManaged(layout)
			cfg, rendered, err := enterprisebundle.LoadConfigForDeviceLayout(b, root, runtime.GOOS, deviceLayout)
			if err != nil {
				t.Fatal(err)
			}
			currentDigest, err := bundleDigester(t.Context(), cfg, rendered, runtime.GOOS, root)
			if err != nil || currentDigest == oldDigest {
				t.Fatalf("upgraded digest %q, err %v", currentDigest, err)
			}
			appVersion = "1.0.4"
			savedInstalled := bundleInstalledConfig
			t.Cleanup(func() { bundleInstalledConfig = savedInstalled })
			bundleInstalledConfig = func(string) ([]byte, error) { return rendered, nil }
			bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
				return &enterprisestatus.PolicyState{EffectiveDigest: currentDigest, GatewayReportedDigest: currentDigest, Applied: true, ConfigGeneration: 17}
			}
			status := func() bundleStatusResult {
				t.Helper()
				out, code := runBundle(t, "status", "--json")
				var result bundleStatusResult
				if err := json.Unmarshal([]byte(out), &result); err != nil || code != 0 {
					t.Fatalf("status exit %d, %v: %s", code, err, out)
				}
				return result
			}
			result := status()
			if !result.Applied || result.Current == nil || result.Current.EffectivePolicyDigest != currentDigest ||
				result.LastReceipt == nil || result.LastReceipt.EffectivePolicyDigest != oldDigest ||
				!hasBundleWarning(result.Warnings, enterprisebundle.WarnDigestUnverifiable) {
				t.Fatalf("upgrade status: %+v", result)
			}
			bundleInstalledConfig = func(string) ([]byte, error) { return append(bytes.Clone(rendered), []byte("# changed\n")...), nil }
			if result := status(); result.Applied {
				t.Fatal("edited installed config was reported as the signed bundle")
			}
			bundleInstalledConfig = func(string) ([]byte, error) { return rendered, nil }
			bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
				return &enterprisestatus.PolicyState{EffectiveDigest: currentDigest, GatewayReportedDigest: oldDigest, Applied: false, ConfigGeneration: 17}
			}
			if result := status(); result.Applied {
				t.Fatal("gateway enforcing the old digest was reported as upgraded bundle")
			}
			bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
				return &enterprisestatus.PolicyState{EffectiveDigest: currentDigest, GatewayReportedDigest: currentDigest, Applied: true, ConfigGeneration: 17}
			}
			if err := os.Remove(filepath.Join(store.LifecycleDir, enterprisebundle.ReceiptsDirName, r.ReceiptID+".json")); err != nil {
				t.Fatal(err)
			}
			if result := status(); !result.Applied || result.LastReceipt != nil || result.Current.EffectivePolicyDigest != currentDigest {
				t.Fatalf("upgrade status after receipt pruning: %+v", result)
			}
			if err := os.Remove(e.anchors); err != nil {
				t.Fatal(err)
			}
			if result := status(); !result.Applied || result.BundleMode || !hasBundleWarning(result.Warnings, "anchor_missing") {
				t.Fatalf("the confirmed bundle stopped being enforced after anchors were removed: %+v", result)
			}
		})
	}
}

// bundleDevice makes the test a standalone managed device with its bundle
// store in a temp dir and anchors trusted without the root-owner check.
func bundleDevice(t *testing.T, e *bundleCLIEnv) *enterprisebundle.Store {
	t.Helper()
	savedStore, savedPolicy, savedAnchors, savedTrust, savedSessions, savedSettle := bundleStore, bundleGatewayPolicy, bundleDefaultAnchors, bundleAnchorTrust, bundleSessionStatus, bundleSettleStatus
	t.Cleanup(func() {
		bundleStore, bundleGatewayPolicy, bundleDefaultAnchors, bundleAnchorTrust = savedStore, savedPolicy, savedAnchors, savedTrust
		bundleSessionStatus = savedSessions
		bundleSettleStatus = savedSettle
	})
	store := enterprisebundle.NewStore(filepath.Join(e.dir, "etc", "bundles"), filepath.Join(e.dir, "lifecycle"))
	t.Cleanup(func() {
		_ = filepath.WalkDir(store.BundlesDir, func(path string, entry fs.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	bundleManagedDevice = func() bool { return true }
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	bundleDefaultAnchors = func() (string, error) { return e.anchors, nil }
	bundleAnchorTrust = nil
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState { return nil }
	bundleSessionStatus = func(context.Context) enterprisestatus.SessionRestartStatus {
		return enterprisestatus.SessionRestartStatus{State: "known", Entries: []enterprisestatus.SessionEntry{}}
	}
	bundleSettleStatus = func(context.Context) error { return nil }
	return store
}

func TestBundleStatusPrivilegeRefusalDoesNotClaimUnmanagedState(t *testing.T) {
	newBundleCLIEnv(t)
	bundlePrivilege = func() error {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeNotAdmin, Detail: "administrator required"}
	}
	bundleManagedDevice = func() bool { t.Fatal("read deployment state before privilege check"); return false }
	out, code := runBundle(t, "status", "--json")
	if code != bundleFailureExitCode() || !strings.Contains(out, `"code": "not_admin"`) ||
		strings.Contains(out, `"bundle_mode"`) || strings.Contains(out, `"current"`) {
		t.Fatalf("privilege refusal exit=%d: %s", code, out)
	}
}

// A status refused before the live session scan (not managed, Secure
// Client, unreadable state) reports the scan as unknown with an empty
// entry list, never the Go zero value {"state":"","entries":null} that the
// published session schema does not allow.
func TestBundleStatusRefusalReportsTheSessionScanAsUnknown(t *testing.T) {
	e := newBundleCLIEnv(t)
	store := bundleDevice(t, e)
	for name, refuse := range map[string]func(){
		"not managed":   func() { bundleManagedDevice = func() bool { return false } },
		"Secure Client": func() { bundleSecureClient = func() bool { return true } },
		"state invalid": func() {
			if err := os.MkdirAll(filepath.Dir(store.StatePath()), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(store.StatePath(), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			savedDevice, savedSC := bundleManagedDevice, bundleSecureClient
			t.Cleanup(func() {
				bundleManagedDevice, bundleSecureClient = savedDevice, savedSC
				_ = os.Remove(store.StatePath())
			})
			refuse()
			out, code := runBundle(t, "status", "--json")
			var res struct {
				OK       bool                                   `json:"ok"`
				Sessions *enterprisestatus.SessionRestartStatus `json:"sessions_restart_required"`
			}
			if err := json.Unmarshal([]byte(out), &res); err != nil || code != bundleFailureExitCode() || res.OK {
				t.Fatalf("exit %d, %v:\n%s", code, err, out)
			}
			if s := res.Sessions; s == nil || s.State != "unknown" || s.Count != 0 || s.Entries == nil || len(s.Entries) != 0 || s.Reason == "" {
				t.Fatalf("sessions_restart_required = %+v:\n%s", s, out)
			}
		})
	}
}

// A Windows receipt that recorded an unfinished session scan must not be
// reported as a digest mismatch (GAP-0104).
func TestBundleReceiptSessionScanWarningIsNotADigestMismatch(t *testing.T) {
	got := bundleReceiptWarningMessage("sessions_scan_unknown", &enterprisebundle.Receipt{})
	if strings.Contains(got, "digest") || !strings.Contains(got, "sessions could not be checked") {
		t.Fatalf("sessions_scan_unknown message = %q", got)
	}
	if got := bundleReceiptWarningMessage(string(enterprisebundle.CodeDigestMismatch), nil); !strings.Contains(got, "differs from the signed expected digest") {
		t.Fatalf("digest mismatch message = %q", got)
	}
}

func TestConfirmedSignerRevocationIsReported(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	bundleDevice(t, e)
	raw, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	writeBundleTestFile(t, e.anchors, bytes.Replace(raw, []byte(`"status":"active"`), []byte(`"status":"revoked"`), 1))
	warning := bundleCurrentSignerWarning(e.anchors, "k1")
	// The warning names the signer, so an anchor-only run that revoked it
	// says which key no longer vouches for the enforcing bundle.
	if warning == nil || warning.Code != string(enterprisebundle.CodeKeyRevoked) || !strings.Contains(warning.Message, "signer k1 is revoked") {
		t.Fatalf("revoked confirmed signer warning = %+v", warning)
	}
}

// The confirmed bundle's signer is checked against the installed anchors
// also after its confirmed receipt was pruned (MaxReceipts newer receipts):
// the store state names the signer.
func TestBundleStatusWarnsOfAnUntrustedSignerAfterTheReceiptWasPruned(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k2": e.edKey.Public()})
	store := bundleDevice(t, e)
	const id = "b-01JA0000000000000000000041"
	digest := "sha256:" + strings.Repeat("4", 64)
	r, err := store.Receive(id, 4, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage(r, &enterprisebundle.Bundle{Files: map[string][]byte{"config.yaml": []byte("config_version: 9\n")}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(r, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
		r.SignerKeyID, r.ManifestSHA256, r.ExpectedDigest = "k1", strings.Repeat("f", 64), digest
		r.SetDigestComparison(true, false, false)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(r); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(r, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) { r.EffectivePolicyDigest = digest }); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm(r); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.LifecycleDir, enterprisebundle.ReceiptsDirName, r.ReceiptID+".json")); err != nil {
		t.Fatal(err)
	}
	out, code := runBundle(t, "status", "--json")
	var result bundleStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil || code != 0 {
		t.Fatalf("status exit %d, %v:\n%s", code, err, out)
	}
	if result.Current == nil || result.Current.BundleID != id || result.LastReceipt != nil ||
		!hasBundleWarning(result.Warnings, string(enterprisebundle.CodeKeyUnknown)) {
		t.Fatalf("pruned confirmed receipt, signer k1 not in the anchors: want key_unknown:\n%s", out)
	}
}

func TestBundleStatusSettlesBeforeReadingCurrent(t *testing.T) {
	e := newBundleCLIEnv(t)
	store := bundleDevice(t, e)
	saved := bundleSettleStatus
	t.Cleanup(func() { bundleSettleStatus = saved })
	const id = "b-01JA0000000000000000000037"
	digest := "sha256:" + strings.Repeat("7", 64)
	called := false
	bundleSettleStatus = func(context.Context) error {
		called = true
		confirmBundle(t, store, id, 7, digest)
		return nil
	}
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{EffectiveDigest: digest, GatewayReportedDigest: digest, Applied: true}
	}
	out, code := runBundle(t, "status", "--json")
	if code != 0 || !called {
		t.Fatalf("status exit=%d, settlement called=%v: %s", code, called, out)
	}
	var result bundleStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Current == nil || result.Current.BundleID != id || !result.Applied || result.LastReceipt == nil || result.LastReceipt.State != enterprisebundle.StateConfirmed {
		t.Fatalf("status did not report settled policy: %s", out)
	}
}

// confirmBundle walks a receipt for id/version to confirmed with digest.
func confirmBundle(t *testing.T, store *enterprisebundle.Store, id string, version uint64, digest string) {
	confirmBundleWithExpected(t, store, id, version, digest, digest, true)
}

func confirmBundleWithExpected(t *testing.T, store *enterprisebundle.Store, id string, version uint64, digest, expected string, comparable bool, disabled ...string) {
	t.Helper()
	confirmBundleReceipt(t, store, id, version, digest, expected, comparable, "", disabled)
}

// confirmBundleDelivery confirms id/version as `bundle apply --delivery-id
// deliveryID` does: the receipt and the state record carry the id.
func confirmBundleDelivery(t *testing.T, store *enterprisebundle.Store, id string, version uint64, digest, deliveryID string) {
	t.Helper()
	confirmBundleReceipt(t, store, id, version, digest, digest, true, deliveryID, nil)
}

func confirmBundleReceipt(t *testing.T, store *enterprisebundle.Store, id string, version uint64, digest, expected string, comparable bool, deliveryID string, disabled []string) {
	t.Helper()
	r, err := store.Receive(id, version, deliveryID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage(r, &enterprisebundle.Bundle{Files: map[string][]byte{"config.yaml": []byte("config_version: 9\n")}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(r, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
		r.ManifestSHA256 = strings.Repeat("f", 64)
		r.ExpectedDigest = expected
		r.SetDigestComparison(comparable, !comparable, false)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(r); err != nil {
		t.Fatal(err)
	}
	if len(disabled) > 0 {
		r.DisabledByBundle = disabled
		r.WarningCodes = []string{"capability_disabled"}
	}
	if err := store.Advance(r, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) { r.EffectivePolicyDigest = digest }); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm(r); err != nil {
		t.Fatal(err)
	}
}

func TestEnterpriseBundleStatusDigestMarkerJSONAndText(t *testing.T) {
	for _, crossVersion := range []bool{false, true} {
		t.Run(fmt.Sprintf("cross_version=%t", crossVersion), func(t *testing.T) {
			e := newBundleCLIEnv(t)
			e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
			store := bundleDevice(t, e)
			digest := "sha256:" + strings.Repeat("8", 64)
			confirmBundleWithExpected(t, store, "b-01JA0000000000000000000036", 1, digest, digest, !crossVersion)
			bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
				return &enterprisestatus.PolicyState{EffectiveDigest: digest, GatewayReportedDigest: digest, Applied: true}
			}
			jsonOut, code := runBundle(t, "status", "--json")
			if code != 0 {
				t.Fatalf("JSON status exit %d: %s", code, jsonOut)
			}
			var result bundleStatusResult
			if err := json.Unmarshal([]byte(jsonOut), &result); err != nil {
				t.Fatal(err)
			}
			textOut, code := runBundle(t, "status")
			if code != 0 {
				t.Fatalf("text status exit %d: %s", code, textOut)
			}
			jsonWarning := hasBundleWarning(result.Warnings, enterprisebundle.WarnDigestUnverifiable)
			textWarning := strings.Contains(textOut, "warning: digest_unverifiable:")
			if jsonWarning != crossVersion || textWarning != crossVersion || result.LastReceipt == nil || result.Bundle == nil ||
				slices.Contains(result.LastReceipt.WarningCodes, enterprisebundle.WarnDigestUnverifiable) != crossVersion ||
				slices.Contains(result.Bundle.WarningCodes, enterprisebundle.WarnDigestUnverifiable) != crossVersion {
				t.Fatalf("cross_version=%t JSON=%s text=%s", crossVersion, jsonOut, textOut)
			}
		})
	}
}

func TestEnterpriseBundleStatusCapabilityLossGolden(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	const id = "b-01JA0000000000000000000035"
	digest := "sha256:" + strings.Repeat("8", 64)
	confirmBundleWithExpected(t, store, id, 1, digest, digest, true, "asset_policy", "sandbox")
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{EffectiveDigest: digest, GatewayReportedDigest: digest, Applied: true}
	}
	out, code := runBundle(t, "status", "--json")
	if code != 0 {
		t.Fatalf("status exit %d: %s", code, out)
	}
	var result bundleStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Bundle == nil || !hasBundleWarning(result.Warnings, "capability_disabled") {
		t.Fatalf("status lost capability warning: %s", out)
	}
	projection, err := json.Marshal(map[string]any{
		"disabled_by_bundle": result.Bundle.DisabledByBundle,
		"warning_code":       result.Warnings[0].Code,
		"warning_message":    result.Warnings[0].Message,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkBundleGolden(t, "status-capability-loss", string(projection), e.dir)
}

func TestEnterpriseBundleStatusWarnsWhenSignedDigestDiffers(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	const id = "b-01JA0000000000000000000034"
	digest, expected := "sha256:"+strings.Repeat("8", 64), "sha256:"+strings.Repeat("2", 64)
	confirmBundleWithExpected(t, store, id, 1, digest, expected, true)
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{EffectiveDigest: digest, GatewayReportedDigest: digest, Applied: true}
	}
	out, code := runBundle(t, "status", "--json")
	if code != 0 {
		t.Fatalf("status exit %d: %s", code, out)
	}
	var status bundleStatusResult
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Applied || status.LastReceipt == nil || status.LastReceipt.ExpectedDigest != expected ||
		!hasBundleWarning(status.Warnings, enterprisebundle.WarnDigestDiffers) ||
		len(status.LastReceipt.WarningCodes) != 1 || status.LastReceipt.WarningCodes[0] != enterprisebundle.WarnDigestDiffers {
		t.Fatalf("status omitted signed digest warning: %s", out)
	}
	publicReceipt, err := os.ReadFile(store.PublicReceiptPath())
	if err != nil || !strings.Contains(string(publicReceipt), `"warning_codes": [`) ||
		!strings.Contains(string(publicReceipt), enterprisebundle.WarnDigestDiffers) {
		t.Fatalf("public receipt omitted signed digest warning: %s (%v)", publicReceipt, err)
	}
	if code := enterprisebundle.DigestWarningCode(expected, digest, false); code != "" {
		t.Fatalf("non-comparable digest difference inferred a cross-version warning: %q", code)
	}
}

func TestEnterpriseBundleStatusRejectsConfigHealthError(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	digest := "sha256:" + strings.Repeat("8", 64)
	confirmBundle(t, store, "b-01JA0000000000000000000046", 1, digest)
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{
			EffectiveDigest: digest, GatewayReportedDigest: digest,
			LastReloadError: "permission denied", Applied: false,
		}
	}
	out, code := runBundle(t, "status", "--json")
	if code != 0 {
		t.Fatalf("status exit %d: %s", code, out)
	}
	var result bundleStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Applied || !hasBundleWarning(result.Warnings, "policy_reload_rejected") {
		t.Fatalf("confirmed digest hid config health error: %s", out)
	}
}

func TestEnterpriseBundleStatusReportsTheEnforcingBundle(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	const goodID, badID = "b-01JA0000000000000000000007", "b-01JA0000000000000000000006"
	digest := "sha256:" + strings.Repeat("1", 64)
	confirmBundle(t, store, goodID, 7, digest)
	bad, err := store.Receive(badID, 6, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Fail(bad, enterprisebundle.CodeVersionNotNewer, "older than the confirmed floor"); err != nil {
		t.Fatal(err)
	}
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{EffectiveDigest: digest, GatewayReportedDigest: digest, Applied: true}
	}

	out, code := runBundle(t, "status", "--json")
	if code != 0 {
		t.Fatalf("status exit %d:\n%s", code, out)
	}
	var res bundleStatusResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.BundleMode || res.Current.BundleID != goodID || res.Floor != 7 || !res.GatewayChecked || !res.Applied ||
		res.LastReceipt.State != enterprisebundle.StateConfirmed || res.LastReceipt.BundleID != goodID ||
		res.Bundle.BundleID != goodID || res.Bundle.State != enterprisebundle.StateConfirmed ||
		res.LastRefusal == nil || res.LastRefusal.BundleID != badID || res.LastRefusal.ErrorCode != string(enterprisebundle.CodeVersionNotNewer) {
		t.Fatalf("status = %s", out)
	}
	projection, err := json.Marshal(map[string]any{
		"current": res.Current.BundleID, "last_receipt": res.LastReceipt.BundleID,
		"bundle": map[string]any{"bundle_id": res.Bundle.BundleID, "version": res.Bundle.Version, "state": res.Bundle.State},
		"last_refusal": map[string]any{
			"bundle_id": res.LastRefusal.BundleID, "version": res.LastRefusal.Version,
			"error_code": res.LastRefusal.ErrorCode, "time": "<time>",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	checkBundleGolden(t, "status-refused-replay", string(projection), e.dir)

	// The gateway enforcing something else is not applied.
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{GatewayReportedDigest: "sha256:" + strings.Repeat("2", 64)}
	}
	if out, _ = runBundle(t, "status", "--json"); !strings.Contains(out, `"applied": false`) {
		t.Fatalf("status with another gateway digest:\n%s", out)
	}

	// A state that cannot be read refuses; it never reads as "no bundle".
	if err := os.WriteFile(store.StatePath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code = runBundle(t, "status", "--json"); code != bundleFailureExitCode() || !strings.Contains(out, `"state_invalid"`) {
		t.Fatalf("corrupt state: exit %d:\n%s", code, out)
	}
	bundleManagedDevice = func() bool { return false }
	if out, code = runBundle(t, "status", "--json"); code != bundleFailureExitCode() || !strings.Contains(out, `"not_managed"`) {
		t.Fatalf("not managed: exit %d:\n%s", code, out)
	}
	bundleSecureClient = func() bool { return true }
	if out, code = runBundle(t, "status", "--json"); code != bundleFailureExitCode() || !strings.Contains(out, `"not_supported_secure_client"`) {
		t.Fatalf("Secure Client: exit %d:\n%s", code, out)
	}
}

func TestEnterpriseBundleStatusSessionGolden(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	confirmBundle(t, store, "b-01JA0000000000000000000032", 1, "sha256:"+strings.Repeat("1", 64))
	saved := bundleSessionStatus
	scans := 0
	bundleSessionStatus = func(context.Context) enterprisestatus.SessionRestartStatus {
		scans++
		return enterprisestatus.SessionRestartStatus{State: "known", Count: 1, Entries: []enterprisestatus.SessionEntry{{PID: 41, User: "alice", Agent: "claudecode", StartedAt: "2026-10-13T07:07:31Z"}}}
	}
	t.Cleanup(func() { bundleSessionStatus = saved })
	out, code := runBundle(t, "status", "--json")
	if code != 0 {
		t.Fatalf("status exit %d: %s", code, out)
	}
	if scans != 1 {
		t.Fatalf("status used %d process scans, want one", scans)
	}
	var res bundleStatusResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(struct {
		Sessions       enterprisestatus.SessionRestartStatus  `json:"sessions_restart_required"`
		BundleSessions *enterprisestatus.SessionRestartStatus `json:"bundle_sessions_restart_required"`
		Warning        bool                                   `json:"sessions_need_restart_warning"`
	}{res.SessionsRestartRequired, res.Bundle.SessionsRestartRequired, hasBundleWarning(res.Warnings, "sessions_need_restart")}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/enterprise_bundle/status-sessions.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got)+"\n" != string(want) {
		t.Fatalf("status session golden:\n%s\nwant:\n%s", got, want)
	}
	var printed bytes.Buffer
	printStatusText(&printed, &res)
	for _, want := range []string{"sessions_need_restart", "pid 41", "user alice", "2026-10-13T07:07:31Z", "restart the agent"} {
		if !strings.Contains(printed.String(), want) {
			t.Fatalf("status text omits %q: %s", want, printed.String())
		}
	}
}

func TestEnterpriseBundleStatusExplainsUnknownSessionScan(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	confirmBundle(t, store, "b-01JA0000000000000000000032", 1, "sha256:"+strings.Repeat("1", 64))
	bundleSessionStatus = func(context.Context) enterprisestatus.SessionRestartStatus {
		return enterprisestatus.SessionRestartStatus{State: "unknown", Entries: []enterprisestatus.SessionEntry{}, Reason: "process snapshot failed"}
	}
	out, code := runBundle(t, "status", "--json")
	if code != 0 || !strings.Contains(out, `"reason": "process snapshot failed"`) || !strings.Contains(out, `"code": "sessions_scan_unknown"`) {
		t.Fatalf("unknown scan exit=%d: %s", code, out)
	}
}

// On a device, verify takes the floor from bundle-state.json: a bundle at
// or below the confirmed version is refused.
func TestEnterpriseBundleVerifyUsesTheDeviceFloor(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	store := bundleDevice(t, e)
	if out, code := runBundle(t, "verify", "--bundle", signed, "--platform", "linux", "--json"); code != 0 {
		t.Fatalf("verify with no confirmed bundle: exit %d:\n%s", code, out)
	}
	confirmBundle(t, store, "b-01JA0000000000000000000006", 6, "sha256:"+strings.Repeat("3", 64))
	out, code := runBundle(t, "verify", "--bundle", signed, "--platform", "linux", "--json")
	if code != bundleFailureExitCode() || !strings.Contains(out, `"version_not_newer"`) ||
		!strings.Contains(out, `"floor": 6`) ||
		!strings.Contains(out, `"floor_source": "last_confirmed_bundle"`) ||
		!strings.Contains(out, "set by the last confirmed bundle") {
		t.Fatalf("verify below the floor: exit %d:\n%s", code, out)
	}
	if err := os.WriteFile(store.StatePath(), []byte(`{"schema_version":1,"floor":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code = runBundle(t, "verify", "--bundle", signed, "--platform", "linux", "--json"); code != bundleFailureExitCode() || !strings.Contains(out, `"state_invalid"`) {
		t.Fatalf("verify with a corrupt state: exit %d:\n%s", code, out)
	}
}

func hasBundleWarning(warnings []enterprisebundle.Warning, code string) bool {
	for _, w := range warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// A device whose managed layout changed its digest (digest_layout_unverifiable)
// enforces its own digest, not the signed standard-layout one, so status must
// not report digest_differs for it even when the signer ran this build; a
// receipt that verified the signed digest still reports a gateway that
// enforces another (GAP-0113 verifier finding 3).
func TestEnterpriseBundleStatusLayoutUnverifiableIsNotDigestDiffers(t *testing.T) {
	for _, layoutDependent := range []bool{false, true} {
		t.Run(fmt.Sprintf("layout_unverifiable=%t", layoutDependent), func(t *testing.T) {
			e := newBundleCLIEnv(t)
			e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
			signed := filepath.Join(e.dir, "v5.dcbundle")
			if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
				t.Fatalf("sign exit %d: %s", code, out)
			}
			b, err := readBundleInput(signed)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := enterprisebundle.DecodeManifest(b.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			expected := manifest.EffectivePolicy.Digests[runtime.GOOS]
			if expected == "" || !enterprisebundle.DigestComparable(manifest, appVersion) {
				t.Fatalf("signed manifest for %s is not comparable on this build: %+v", runtime.GOOS, manifest.EffectivePolicy)
			}
			device := "sha256:" + strings.Repeat("8", 64)
			store := bundleDevice(t, e)
			r, err := store.Receive(manifest.BundleID, manifest.Version, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Stage(r, b); err != nil {
				t.Fatal(err)
			}
			if err := store.Advance(r, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
				r.ManifestSHA256, r.ExpectedDigest = strings.Repeat("f", 64), expected
				r.SetDigestComparison(!layoutDependent, false, layoutDependent)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Promote(r); err != nil {
				t.Fatal(err)
			}
			if err := store.Advance(r, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) { r.EffectivePolicyDigest = device }); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Confirm(r); err != nil {
				t.Fatal(err)
			}
			bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
				return &enterprisestatus.PolicyState{EffectiveDigest: device, GatewayReportedDigest: device, Applied: true}
			}
			out, code := runBundle(t, "status", "--json")
			if code != 0 {
				t.Fatalf("status exit %d: %s", code, out)
			}
			var status bundleStatusResult
			if err := json.Unmarshal([]byte(out), &status); err != nil {
				t.Fatal(err)
			}
			if !status.Applied || hasBundleWarning(status.Warnings, enterprisebundle.WarnDigestDiffers) == layoutDependent ||
				hasBundleWarning(status.Warnings, enterprisebundle.WarnDigestLayoutUnverifiable) != layoutDependent ||
				hasBundleWarning(status.Warnings, enterprisebundle.WarnDigestUnverifiable) {
				t.Fatalf("layout_unverifiable=%t status: %s", layoutDependent, out)
			}
		})
	}
}

// An installed anchor file that fails its checks is explained by a warning
// on a device with no confirmed bundle too, so the absent anchors_summary
// is never silent: malformed is anchor_invalid, untrusted anchor_insecure.
func TestBundleStatusWarnsOfAnInvalidAnchorFileWithoutAConfirmedBundle(t *testing.T) {
	e := newBundleCLIEnv(t)
	bundleDevice(t, e)
	writeBundleTestFile(t, e.anchors, []byte("{not json"))
	status := func() bundleStatusResult {
		t.Helper()
		out, code := runBundle(t, "status", "--json")
		var result bundleStatusResult
		if err := json.Unmarshal([]byte(out), &result); err != nil || code != 0 {
			t.Fatalf("status exit %d, %v:\n%s", code, err, out)
		}
		if !result.BundleMode || result.Current != nil || result.AnchorsSummary != nil {
			t.Fatalf("fresh device with a bad anchor file: bundle_mode %v, current %+v, anchors_summary %+v", result.BundleMode, result.Current, result.AnchorsSummary)
		}
		return result
	}
	if result := status(); !hasBundleWarning(result.Warnings, string(enterprisebundle.CodeAnchorInvalid)) {
		t.Fatalf("malformed anchor file: warnings %+v, want anchor_invalid", result.Warnings)
	}
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	bundleAnchorTrust = func(string) error { return errors.New("the anchor file is writable by another account") }
	if result := status(); !hasBundleWarning(result.Warnings, string(enterprisebundle.CodeAnchorInsecure)) {
		t.Fatalf("untrusted anchor file: warnings %+v, want anchor_insecure", result.Warnings)
	}
}
