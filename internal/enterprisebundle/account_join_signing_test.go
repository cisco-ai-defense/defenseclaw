// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// confirmAccountJoinBundle confirms bundle version v whose config.yaml is
// config and whose manifest says it was signed at created.
func confirmAccountJoinBundle(t *testing.T, s *Store, v uint64, config, created string) {
	t.Helper()
	b := storeBundle()
	b.Files[ConfigName] = []byte(config)
	m := validManifest()
	m.BundleID, m.Version, m.CreatedAt, m.MinProductVersion = testBundleID(1), v, created, "1.0.7"
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

// rel-1-0-6:GAP-0277: the device bounds the account join overlap by the
// created_at of the confirmed bundle, only while that bundle's config sets
// the next_generation and next_not_after installed now.
func TestConfirmedAccountJoinSignedAt(t *testing.T) {
	s := testStore(t)
	notAfter := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	if _, ok := s.ConfirmedAccountJoinSignedAt(2, notAfter); ok {
		t.Fatal("no confirmed bundle has a signing time")
	}
	const config = "config_version: 9\nenterprise:\n  account_join:\n    mode: on\n    generation: 1\n    next_generation: 2\n    next_not_after: \"2026-11-20T00:00:00Z\"\n"
	confirmAccountJoinBundle(t, s, 1, config, "2026-10-25T08:30:00Z")
	at, ok := s.ConfirmedAccountJoinSignedAt(2, notAfter)
	if !ok || !at.Equal(time.Date(2026, 10, 25, 8, 30, 0, 0, time.UTC)) {
		t.Fatalf("signing time %v, %v; want 2026-10-25T08:30:00Z", at, ok)
	}
	// The same instant in another zone is the same next_not_after.
	if _, ok := s.ConfirmedAccountJoinSignedAt(2, notAfter.In(time.FixedZone("x", 3600))); !ok {
		t.Fatal("the same instant in another zone is refused")
	}
	for name, check := range map[string]func() bool{
		"other generation":     func() bool { _, ok := s.ConfirmedAccountJoinSignedAt(3, notAfter); return ok },
		"other next_not_after": func() bool { _, ok := s.ConfirmedAccountJoinSignedAt(2, notAfter.Add(time.Hour)); return ok },
	} {
		if check() {
			t.Errorf("%s: a config the confirmed bundle does not carry got its signing time", name)
		}
	}
	// A config without the next generation carries no overlap.
	confirmAccountJoinBundle(t, s, 2, "config_version: 9\nenterprise:\n  account_join:\n    mode: on\n    generation: 2\n", "2026-10-26T08:30:00Z")
	if _, ok := s.ConfirmedAccountJoinSignedAt(2, notAfter); ok {
		t.Fatal("a bundle without next_generation gave a signing time")
	}
	// A damaged confirmed config gives none: the device clock decides.
	confirmAccountJoinBundle(t, s, 3, config, "2026-10-27T08:30:00Z")
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.VersionDir(st.Current.Dir), ConfigName)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(config+"# changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ConfirmedAccountJoinSignedAt(2, notAfter); ok {
		t.Fatal("a changed confirmed config gave a signing time")
	}
}
