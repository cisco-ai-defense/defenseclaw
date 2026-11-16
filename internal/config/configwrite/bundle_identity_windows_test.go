// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package configwrite

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// W4b loop round 2: a junction (a directory reparse point that needs no
// privilege to create) where the generation record belongs, dangling or
// not, is not a record. The equal-byte bundle binding refuses and leaves it.
func TestEqualByteBundleBindingRefusesAGenerationJunction(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		path := writeTestConfig(t, "deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\nobservability: {}\n")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", GenerationPath(path), target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v: %s", err, out)
		}
		if dangling {
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
		}
		opt := Options{Actor: "operator:test", Lifecycle: true, ExpectSHA256: SHA256Hex(raw),
			Bundle: BundleRef{ID: "b-01J9ZZZZZZZZZZZZZZZZZZZZZZ", Version: 1, SignerKeyID: "k1"}}
		if _, err := ReplaceDocument(context.Background(), path, raw, opt); !errors.Is(err, ErrUnprovenBundleBinding) {
			t.Fatalf("dangling=%v: equal-byte bundle over a junction: %v", dangling, err)
		}
		if _, err := Locked(context.Background(), path, opt, func() (bool, error) { return true, nil }); !errors.Is(err, ErrUnprovenBundleBinding) {
			t.Fatalf("dangling=%v: Locked bundle over a junction: %v", dangling, err)
		}
		if info, err := os.Lstat(GenerationPath(path)); err != nil || info.Mode().IsRegular() {
			t.Fatalf("dangling=%v: the refusal replaced the junction: %v, %v", dangling, info, err)
		}
	}
}
