// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The cache never outlives a change it judged: a root replaced by a
// junction, an attribute or access-list change, an expired entry and a
// failed validation all run the full check on the next call.
func TestGAP0011TheMachineRootCacheFailsClosed(t *testing.T) {
	t.Run("junction swap", func(t *testing.T) {
		root := freshMachineRoot(t)
		if _, err := ValidateTrustedMachineRoot(root, "test"); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(filepath.Dir(root), "Elsewhere")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(root); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", root, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("cmd", "/c", "rmdir", root).Run() })
		if _, err := ValidateTrustedMachineRoot(root, "test"); err == nil {
			t.Fatal("a root replaced by a junction was trusted from the cache")
		}
	})
	t.Run("access list change", func(t *testing.T) {
		root := freshMachineRoot(t)
		queries := countMountedVolumeQueries(t)
		if _, err := ValidateTrustedMachineRoot(root, "test"); err != nil {
			t.Fatal(err)
		}
		before := *queries
		if out, err := exec.Command("icacls", root, "/grant", "*S-1-5-32-545:(RX)").CombinedOutput(); err != nil {
			t.Fatalf("icacls: %v %s", err, out)
		}
		if _, err := ValidateTrustedMachineRoot(root, "test"); err != nil {
			t.Fatal(err)
		}
		if *queries == before {
			t.Fatal("an access-list change on the root did not run the full check again")
		}
	})
	t.Run("hidden attribute change", func(t *testing.T) {
		root := freshMachineRoot(t)
		queries := countMountedVolumeQueries(t)
		if _, err := ValidateTrustedMachineRoot(root, "test"); err != nil {
			t.Fatal(err)
		}
		before := *queries
		if out, err := exec.Command("attrib", "+h", root).CombinedOutput(); err != nil {
			t.Fatalf("attrib: %v %s", err, out)
		}
		if _, err := ValidateTrustedMachineRoot(root, "test"); err != nil {
			t.Fatal(err)
		}
		if *queries == before {
			t.Fatal("an attribute change on the root did not run the full check again")
		}
	})
	t.Run("expired", func(t *testing.T) {
		root := freshMachineRoot(t)
		queries := countMountedVolumeQueries(t)
		saved := trustedMachineRootNow
		t.Cleanup(func() { trustedMachineRootNow = saved })
		if _, err := ValidateTrustedMachineRoot(root, "test"); err != nil {
			t.Fatal(err)
		}
		before := *queries
		later := saved().Add(trustedMachineRootCacheMaxAge)
		trustedMachineRootNow = func() time.Time { return later }
		if _, err := ValidateTrustedMachineRoot(root, "test"); err != nil {
			t.Fatal(err)
		}
		if *queries == before {
			t.Fatal("an entry at its maximum age was served from the cache")
		}
	})
	t.Run("failure is not kept", func(t *testing.T) {
		missing := filepath.Join(freshMachineRoot(t), "Missing")
		calls := 0
		saved := trustedMachineRootValidateUncached
		t.Cleanup(func() { trustedMachineRootValidateUncached = saved })
		trustedMachineRootValidateUncached = func(value, label string) (string, error) {
			calls++
			return saved(value, label)
		}
		for i := 0; i < 3; i++ {
			if _, err := ValidateTrustedMachineRoot(missing, "test"); err == nil {
				t.Fatal("a missing root was trusted")
			}
		}
		if calls != 3 {
			t.Fatalf("a failed validation was kept: %d full checks for 3 calls", calls)
		}
	})
	t.Run("unusable value is not cached", func(t *testing.T) {
		if watches := openTrustedMachineRootWatches(`relative\root`); watches != nil {
			closeTrustedMachineRootWatches(watches)
			t.Fatal("a relative value got change notifications")
		}
	})
}
