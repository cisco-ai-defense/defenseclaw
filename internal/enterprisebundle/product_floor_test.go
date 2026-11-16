// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// confirmFloorBundle confirms bundle n version v whose manifest sets floor as
// its min_product_version.
func confirmFloorBundle(t *testing.T, s *Store, n int, v uint64, floor string) {
	t.Helper()
	b := storeBundle()
	m := validManifest()
	m.BundleID, m.Version, m.MinProductVersion = testBundleID(n), v, floor
	m.Files = FileEntries(b)
	b.Manifest = marshal(t, m)
	sum := sha256.Sum256(b.Manifest)
	r, err := s.Receive(m.BundleID, v, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stage(r, b); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(r, StateVerified, func(r *Receipt) {
		r.TenantID, r.DeviceGroup, r.SignerKeyID, r.Principal = "acme", "eng-laptops", "k1", "control-plane:acme/alice"
		r.ManifestSHA256 = hex.EncodeToString(sum[:])
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Promote(r); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(r, StateApplied, func(r *Receipt) {
		r.EffectivePolicyDigest, r.ConfigGeneration, r.AppliedAt = "sha256:"+digestOf(r.ReceiptID+"p"), 40+v, "2026-10-12T10:00:00.000Z"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm(r); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmedProductFloorIsTheConfirmedBundleMinimum(t *testing.T) {
	s := testStore(t)
	if floor, err := s.ConfirmedProductFloor(); err != nil || floor != "" {
		t.Fatalf("no bundle: floor %q, %v; want none", floor, err)
	}
	confirmFloorBundle(t, s, 1, 1, "1.0.4")
	if floor, err := s.ConfirmedProductFloor(); err != nil || floor != "1.0.4" {
		t.Fatalf("confirmed floor %q, %v; want 1.0.4", floor, err)
	}
	// A later bundle lowers the floor.
	confirmFloorBundle(t, s, 1, 2, "")
	if floor, err := s.ConfirmedProductFloor(); err != nil || floor != "" {
		t.Fatalf("lowered floor %q, %v; want none", floor, err)
	}
}

func TestConfirmedProductFloorSurvivesDamagedBundleConfigButNotManifest(t *testing.T) {
	s := testStore(t)
	confirmFloorBundle(t, s, 1, 1, "1.0.4")
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	dir := s.VersionDir(st.Current.Dir)
	configPath := filepath.Join(dir, ConfigName)
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("damaged: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if floor, err := s.ConfirmedProductFloor(); err != nil || floor != "1.0.4" {
		t.Fatalf("damaged config: floor %q, %v; want authenticated 1.0.4", floor, err)
	}
	manifestPath := filepath.Join(dir, ManifestName)
	if err := os.Chmod(manifestPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if floor, err := s.ConfirmedProductFloor(); err == nil || floor != "" {
		t.Fatalf("changed manifest: floor %q, %v; want refusal", floor, err)
	}
}

func TestReleaseFloorRefusalAndBelowFloorWarning(t *testing.T) {
	for _, tc := range []struct {
		version, floor string
		refused        bool
	}{
		{"1.0.4", "", false}, {"dev", "", false},
		{"1.0.6", "1.0.7", true}, {"1.0.7", "1.0.7", false}, {"v1.0.8", "1.0.7", false},
		{"dev", "1.0.4", true}, {"", "1.0.4", true}, {"1.0.x", "1.0.4", true},
	} {
		if err := ReleaseFloorRefusal(tc.version, tc.floor); (err != nil) != tc.refused {
			t.Fatalf("ReleaseFloorRefusal(%q, %q) = %v, want refused %t", tc.version, tc.floor, err, tc.refused)
		}
	}

	s := testStore(t)
	if w := s.ProductBelowFloorWarning("1.0.4"); w != nil {
		t.Fatalf("no bundle: %+v", w)
	}
	confirmFloorBundle(t, s, 1, 1, "1.0.7")
	for _, tc := range []struct {
		version string
		warned  bool
	}{{"1.0.6", true}, {"1.0.7", false}, {"1.1.0", false}, {"dev", false}} {
		w := s.ProductBelowFloorWarning(tc.version)
		if (w != nil) != tc.warned || (w != nil && (w.Code != WarnProductBelowFloor || !strings.Contains(w.Message, "1.0.7"))) {
			t.Fatalf("running %s under floor 1.0.7: %+v, want warned %t", tc.version, w, tc.warned)
		}
	}
}
