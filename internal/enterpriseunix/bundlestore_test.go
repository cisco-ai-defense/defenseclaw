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
	good, err := store.Receive(goodID, 3)
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
	if _, err := store.Receive(newID, 4); err != nil {
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
