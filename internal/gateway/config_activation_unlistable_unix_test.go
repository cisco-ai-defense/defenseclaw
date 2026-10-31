//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// The bundle store is 0711 (rel-1-0-6:GAP-0038): the gateway's service
// account cannot list it. The signed-activation check and the start fallback
// still find the version directories by name: the bundle the generation
// record names by its bundle id, and the start fallback from the public
// receipt events. Without that every
// signed bundle apply on managed Linux failed not_confirmed and rolled back
// (found on dc-ubuntu-eh by fix/r106-1391).
func TestSignedActivationFindsVersionsInAnUnlistableStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	dir := t.TempDir()
	s := newSignedStore(t, dir)
	const first = "b-01M67Q3D91SE476NFVDCN0BDQZ"
	const second = "b-01M67QDN97GZ201W27K06BENYS"
	source := []byte("config_version: 9\n")
	rendered := s.store(t, first, 1, source)
	redelivered := s.store(t, second, 2, source)
	bundles := filepath.Join(dir, enterprisebundle.BundlesDirName)
	events := filepath.Join(bundles, "receipt-events")
	if err := os.MkdirAll(events, 0o755); err != nil {
		t.Fatal(err)
	}
	event := fmt.Sprintf(`{"schema_version":1,"receipt_id":%q,"bundle_id":%q,"version":2,"state":"confirmed"}`, second, second)
	if err := os.WriteFile(filepath.Join(events, second+".json"), []byte(event), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bundles, 0o311); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bundles, 0o755) })
	if _, err := os.ReadDir(bundles); err == nil {
		t.Skip("this file system lists a directory without read permission")
	}
	anchors, raw, err := enterprisebundle.ReadAnchorsFile(filepath.Join(dir, "trust", enterprisebundle.AnchorsName), nil)
	if err != nil {
		t.Fatal(err)
	}
	in := enterprisebundle.ActivationInput{BundlesDir: bundles, Platform: runtime.GOOS, Anchors: anchors, AnchorsRaw: raw}
	if _, refusal := enterprisebundle.CheckSignedActivation(in, first, 1, "k1", rendered); refusal != nil {
		t.Fatalf("first delivery in an unlistable store: %+v", refusal)
	}
	if _, refusal := enterprisebundle.CheckSignedActivation(in, second, 2, "k1", redelivered); refusal != nil {
		t.Fatalf("second bundle in an unlistable store: %+v", refusal)
	}
	if versions := enterprisebundle.SignedVersions(in); len(versions) != 1 || versions[0].Manifest.BundleID != second {
		t.Fatalf("start fallback versions = %d", len(versions))
	}
	if _, refusal := enterprisebundle.CheckSignedActivation(in, first, 1, "k1", []byte("config_version: 9\nother: 1\n")); refusal == nil {
		t.Fatal("bytes the bundle does not render were admitted")
	}
}
