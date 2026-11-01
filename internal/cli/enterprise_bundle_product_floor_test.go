// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// confirmFloorBundleCLI signs a bundle with --min-product-version floor
// ("" for none) and confirms it in the device store, as an apply does.
func confirmFloorBundleCLI(t *testing.T, e *bundleCLIEnv, store *enterprisebundle.Store, version int, floor string) {
	t.Helper()
	signed := filepath.Join(e.dir, fmt.Sprintf("floor-%d.dcbundle", version))
	args := e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")
	for i := range args {
		if args[i] == "--version" && i+1 < len(args) {
			args[i+1] = fmt.Sprint(version)
		}
	}
	if floor != "" {
		args = append(args, "--min-product-version", floor)
	}
	if out, code := runBundle(t, args...); code != 0 {
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
	store.SealVersion = func(string) error { return nil }
	r, err := store.Receive(manifest.BundleID, manifest.Version, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage(r, b); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b.Manifest)
	if err := store.Advance(r, enterprisebundle.StateVerified, func(rc *enterprisebundle.Receipt) {
		rc.ManifestSHA256 = fmt.Sprintf("%x", sum)
		rc.SignerKeyID, rc.Principal = "k1", manifest.CreatedBy
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(r); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(r, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
		rc.EffectivePolicyDigest, rc.ConfigGeneration = "sha256:"+strings.Repeat("1", 64), uint64(10+version)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm(r); err != nil {
		t.Fatal(err)
	}
}

// Windows Setup refuses a payload below the confirmed bundle's release
// floor (private #8), before anything changes, only while trust anchors
// are installed, and fails closed on a floor it cannot read.
func TestWindowsSetupProductFloorRefusal(t *testing.T) {
	e := newBundleCLIEnv(t)
	store := bundleDevice(t, e)

	// No trust anchors: no check, whatever the version.
	if err := windowsSetupProductFloorRefusal("dev"); err != nil {
		t.Fatalf("no anchors: %v", err)
	}
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	// Anchors and no confirmed bundle: no floor.
	if err := windowsSetupProductFloorRefusal("1.0.4"); err != nil {
		t.Fatalf("no confirmed bundle: %v", err)
	}
	confirmFloorBundleCLI(t, e, store, 2, "1.0.7")
	for _, tc := range []struct {
		candidate string
		refused   bool
	}{
		{"1.0.6", true}, {"1.0.4", true}, {"dev", true}, {"", true},
		{"1.0.7", false}, {"v1.0.7", false}, {"1.0.8", false}, {"1.1.0", false},
	} {
		err := windowsSetupProductFloorRefusal(tc.candidate)
		if tc.refused != (err != nil) {
			t.Fatalf("candidate %q: refusal %v, want refused %t", tc.candidate, err, tc.refused)
		}
		if err != nil && (windowsEnterpriseMessageCodeOf(err) != windowsProductFloorRefused || !strings.Contains(err.Error(), "nothing was changed")) {
			t.Fatalf("candidate %q: %v, want product_floor_refused", tc.candidate, err)
		}
	}
	// A signed bundle with a lower floor lets the rollback to 1.0.4 through.
	confirmFloorBundleCLI(t, e, store, 3, "1.0.4")
	if err := windowsSetupProductFloorRefusal("1.0.4"); err != nil {
		t.Fatalf("floor lowered to 1.0.4: %v", err)
	}
	confirmFloorBundleCLI(t, e, store, 4, "")
	if err := windowsSetupProductFloorRefusal("1.0.4"); err != nil {
		t.Fatalf("floor removed: %v", err)
	}

	// A confirmed manifest that no longer matches its pinned hash refuses.
	st, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(store.VersionDir(st.Current.Dir), enterprisebundle.ManifestName)
	_ = os.Chmod(manifest, 0o600)
	if err := os.WriteFile(manifest, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := windowsSetupProductFloorRefusal("1.0.9"); err == nil || windowsEnterpriseMessageCodeOf(err) != windowsProductFloorRefused {
		t.Fatalf("damaged manifest: %v, want product_floor_refused", err)
	}
}

// windowsEnterpriseMessageCodeOf is the leading code of a Windows lifecycle
// message ("code: detail").
func windowsEnterpriseMessageCodeOf(err error) string {
	code, _, _ := strings.Cut(err.Error(), ":")
	return code
}

// bundle status reports the confirmed bundle's release floor as
// current.min_product_version (absent without one) and warns
// product_below_floor, still ok, when this build is below it.
func TestBundleStatusReportsTheReleaseFloor(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	status := func() (map[string]any, bundleStatusResult) {
		t.Helper()
		out, code := runBundle(t, "status", "--json")
		doc := schemas.Validate(t, "bundle-status.schema.json", []byte(out))
		if code != 0 {
			t.Fatalf("status exit %d: %s", code, out)
		}
		var res bundleStatusResult
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatal(err)
		}
		return doc, res
	}
	confirmFloorBundleCLI(t, e, store, 2, "")
	doc, res := status()
	if _, ok := doc["current"].(map[string]any)["min_product_version"]; ok || hasBundleWarning(res.Warnings, enterprisebundle.WarnProductBelowFloor) {
		t.Fatalf("no floor: %+v", doc)
	}

	appVersion = "1.0.6"
	confirmFloorBundleCLI(t, e, store, 3, "1.0.6")
	doc, res = status()
	if res.Current == nil || res.Current.MinProductVersion != "1.0.6" || hasBundleWarning(res.Warnings, enterprisebundle.WarnProductBelowFloor) {
		t.Fatalf("at the floor: current %+v warnings %+v", res.Current, res.Warnings)
	}
	if lastGood, ok := doc["last_good"].(map[string]any); ok {
		if _, ok := lastGood["min_product_version"]; ok {
			t.Fatal("last_good carries min_product_version")
		}
	}

	// The device runs below the floor (an older Setup without the check put
	// it there): a warning, status stays ok.
	appVersion = "1.0.5"
	_, res = status()
	if !res.OK || !hasBundleWarning(res.Warnings, enterprisebundle.WarnProductBelowFloor) {
		t.Fatalf("below the floor: ok %t warnings %+v", res.OK, res.Warnings)
	}
	if out, _ := runBundle(t, "status"); !strings.Contains(out, "Release floor: DefenseClaw 1.0.6 or later") {
		t.Fatalf("text status:\n%s", out)
	}
}
