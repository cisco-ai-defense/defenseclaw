// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// Every changing run settles the bundle store after it restored a pending
// transaction: a bundle a crashed run received fails as interrupted, the
// result carries the bundle block naming the bundle that still enforces,
// and policy-state.json names the bundle of the recorded config generation.
func TestLifecycleSettlesBundlesAndReportsTheBundleBlock(t *testing.T) {
	const computed = "sha256:" + "cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34"
	h := newTestHost(t, "linux")
	h.env.Runner = &policyDigestRunner{fakeRunner: h.runner, digest: computed}
	reported, reloadError := computed, ""
	servePolicyHealth(h, &reported, &reloadError)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))

	store := h.env.bundleStore()
	// Version directories are read-only; open them up before TempDir removes them.
	t.Cleanup(func() {
		_ = filepath.WalkDir(store.BundlesDir, func(path string, entry fs.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	const goodID, newID = "b-01JA0000000000000000000001", "b-01JA0000000000000000000002"
	good, err := store.Receive(goodID, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage(good, &enterprisebundle.Bundle{Files: map[string][]byte{"config.yaml": []byte("config_version: 9\n")}}); err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error {
			return store.Advance(good, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) { r.ManifestSHA256 = strings.Repeat("e", 64) })
		},
		func() error { _, err := store.Promote(good); return err },
		func() error {
			return store.Advance(good, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) { r.EffectivePolicyDigest = computed })
		},
		func() error { _, err := store.Confirm(good); return err },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Receive(newID, 4, ""); err != nil {
		t.Fatal(err)
	}

	// The lifecycle recorded the installed config of bundle 3 in generation 4.
	genPath := configwrite.GenerationPath(h.env.P(h.env.Layout.ConfigPath))
	raw, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatal(err)
	}
	var gen map[string]any
	if err := json.Unmarshal(raw, &gen); err != nil {
		t.Fatal(err)
	}
	gen["generation"], gen["bundle_id"], gen["bundle_version"] = 4, goodID, 3
	raw, _ = json.Marshal(gen)
	if err := os.WriteFile(genPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	r := h.run(Options{Action: ActionRepair})
	if !hasWarning(r, codeBundleInterrupted) {
		t.Fatalf("repair did not settle the interrupted bundle: %+v", r.Warnings)
	}
	b := r.Bundle
	if b == nil || b.BundleID != goodID || b.State != enterprisebundle.StateConfirmed ||
		r.LastRefusal == nil || r.LastRefusal.BundleID != newID || r.LastRefusal.ErrorCode != string(enterprisebundle.CodeInterrupted) {
		t.Fatalf("bundle block = %+v", b)
	}
	if record, err := h.env.loadPolicyState(); err != nil || record == nil || record.BundleID != goodID || record.BundleVersion != 3 {
		t.Fatalf("policy-state.json = %+v, %v", record, err)
	}
	if st, err := store.LoadState(); err != nil || st.Current.BundleID != goodID || st.Floor != 3 {
		t.Fatalf("settle changed the bundle state: %+v, %v", st, err)
	}
	if status := h.run(Options{Action: ActionStatus}); status.Bundle == nil || status.Bundle.State != enterprisebundle.StateConfirmed || status.LastRefusal == nil {
		t.Fatalf("status bundle block = %+v", status.Bundle)
	}
}

func TestBundleReceiptPublicAndStoreChildrenPrivate(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			store := h.env.bundleStore()
			r, err := store.Receive("b-01JA0000000000000000000001", 1, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Fail(r, enterprisebundle.CodeSignatureInvalid, "invalid signature"); err != nil {
				t.Fatal(err)
			}
			state := store.StatePath()
			if err := os.WriteFile(state, []byte("{\"schema_version\":1,\"floor\":0}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			h.owners[state] = [2]int{0, 0}
			privateReceipt := filepath.Join(store.LifecycleDir, enterprisebundle.ReceiptsDirName, r.ReceiptID+".json")
			publicEvent := filepath.Join(store.PublicReceiptEventsDir(), r.ReceiptID+".json")
			staging := filepath.Join(store.BundlesDir, ".staging-test")
			if err := os.Mkdir(staging, 0o700); err != nil {
				t.Fatal(err)
			}
			version := filepath.Join(store.BundlesDir, enterprisebundle.VersionDirNameForReceipt(1, r.BundleID, r.ReceiptID))
			if err := os.Mkdir(version, 0o750); err != nil {
				t.Fatal(err)
			}
			versionAsset := filepath.Join(version, enterprisebundle.ManifestName)
			if err := os.WriteFile(versionAsset, []byte("{}"), 0o640); err != nil {
				t.Fatal(err)
			}
			service := h.accounts.accounts[h.env.Layout.ServiceUser]
			for _, path := range []string{store.PublicReceiptPath(), privateReceipt, staging} {
				h.owners[path] = [2]int{0, 0}
			}
			for _, path := range []string{version, versionAsset} {
				h.owners[path] = [2]int{0, service.GID}
			}
			check := func(path string, want os.FileMode) {
				t.Helper()
				info, err := os.Lstat(path)
				if err != nil || info.Mode().Perm() != want {
					t.Fatalf("%s mode = %v, %v; want %04o", path, info, err, want)
				}
			}
			check(store.BundlesDir, 0o711)
			check(store.PublicReceiptPath(), 0o644)
			check(store.PublicReceiptEventsDir(), 0o755)
			check(publicEvent, 0o644)
			check(state, 0o600)
			check(privateReceipt, 0o600)
			check(h.env.bundleInboxDir(), 0o700)
			check(staging, 0o700)
			check(version, 0o750)
			check(versionAsset, 0o640)
			if goos == "darwin" {
				targets := map[string]bool{}
				for _, target := range h.env.aclTargets(nil, nil) {
					targets[target.path] = target.private
				}
				for _, path := range []string{state, privateReceipt, h.env.bundleInboxDir(), staging, version, versionAsset} {
					if !targets[path] {
						t.Fatalf("private bundle path %s is not checked for macOS read ACLs", path)
					}
				}
				if targets[store.PublicReceiptPath()] {
					t.Fatal("public receipt is treated as private by the macOS ACL check")
				}
				if targets[store.PublicReceiptEventsDir()] || targets[publicEvent] {
					t.Fatal("public receipt spool is treated as private by the macOS ACL check")
				}
			}
			writeFreshLedger(t, h)
			if err := os.Chmod(versionAsset, 0o777); err != nil {
				t.Fatal(err)
			}
			versionDrift := h.run(Options{Action: ActionVerify})
			requireError(t, versionDrift, codeVerify)
			if !strings.Contains(messagesOf(versionDrift.Errors, codeVerify), enterprisebundle.ManifestName) {
				t.Fatalf("verify missed world-readable version asset: %+v", versionDrift.Errors)
			}
			if err := os.Chmod(versionAsset, 0o640); err != nil {
				t.Fatal(err)
			}

			for _, path := range []string{store.PublicReceiptPath(), state, privateReceipt, h.env.bundleInboxDir(), staging} {
				if err := os.Chmod(path, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			verify := h.run(Options{Action: ActionVerify})
			requireError(t, verify, codeVerify)
			for _, path := range []string{store.PublicReceiptPath(), state, privateReceipt, h.env.bundleInboxDir(), staging} {
				if !strings.Contains(messagesOf(verify.Errors, codeVerify), filepath.Base(path)) {
					t.Fatalf("verify missed %s mode drift: %+v", path, verify.Errors)
				}
			}
			requireOK(t, h.run(Options{Action: ActionRepair}))
			check(store.PublicReceiptPath(), 0o644)
			check(state, 0o600)
			check(privateReceipt, 0o600)
			check(h.env.bundleInboxDir(), 0o700)
		})
	}
}
