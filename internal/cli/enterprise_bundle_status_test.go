// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// bundleDevice makes the test a standalone managed device with its bundle
// store in a temp dir and anchors trusted without the root-owner check.
func bundleDevice(t *testing.T, e *bundleCLIEnv) *enterprisebundle.Store {
	t.Helper()
	savedStore, savedPolicy, savedAnchors, savedTrust := bundleStore, bundleGatewayPolicy, bundleDefaultAnchors, bundleAnchorTrust
	t.Cleanup(func() {
		bundleStore, bundleGatewayPolicy, bundleDefaultAnchors, bundleAnchorTrust = savedStore, savedPolicy, savedAnchors, savedTrust
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
	return store
}

// confirmBundle walks a receipt for id/version to confirmed with digest.
func confirmBundle(t *testing.T, store *enterprisebundle.Store, id string, version uint64, digest string) {
	confirmBundleWithExpected(t, store, id, version, digest, digest, true)
}

func confirmBundleWithExpected(t *testing.T, store *enterprisebundle.Store, id string, version uint64, digest, expected string, comparable bool) {
	t.Helper()
	r, err := store.Receive(id, version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage(r, &enterprisebundle.Bundle{Files: map[string][]byte{"config.yaml": []byte("config_version: 9\n")}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(r, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
		r.ManifestSHA256 = strings.Repeat("f", 64)
		r.ExpectedDigest, r.DigestComparable = expected, comparable
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
	if code := enterprisebundle.DigestWarningCode(expected, digest, false); code != enterprisebundle.WarnDigestUnverifiable {
		t.Fatalf("cross-version digest warning = %q", code)
	}
}

func TestEnterpriseBundleStatusReportsTheEnforcingBundle(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	const goodID, badID = "b-01JA0000000000000000000007", "b-01JA0000000000000000000006"
	digest := "sha256:" + strings.Repeat("1", 64)
	confirmBundle(t, store, goodID, 7, digest)
	bad, err := store.Receive(badID, 6)
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
	if code != bundleFailureExitCode() || !strings.Contains(out, `"version_not_newer"`) || !strings.Contains(out, `"floor": 6`) {
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
