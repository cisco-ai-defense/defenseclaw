//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// clusterSecretVolume lays dir out as Kubernetes writes a Secret volume:
// <dir>/<key> -> ..data/<key> -> ..<timestamp>/<key>.
func clusterSecretVolume(t *testing.T, keys map[string]string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	stamp := filepath.Join(dir, "..2026_11_17_22_00_00.000000001")
	if err := os.Mkdir(stamp, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range keys {
		if err := os.WriteFile(filepath.Join(stamp, k), []byte(v+"\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(stamp, k), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Base(stamp), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for k := range keys {
		if err := os.Symlink(filepath.Join("..data", k), filepath.Join(dir, k)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// GAP-0560: a managed Agent Substrate gateway reads its service credentials
// (the LLM judge key that enterprise.inspection.llm.credential names) from
// the chart's mounted LLM credentials Secret.
func TestGAP0560ClusterSecretIsAServiceCredentialSource(t *testing.T) {
	t.Cleanup(func() { UseClusterCredentialDir("") })
	dir := clusterSecretVolume(t, map[string]string{"bedrock": "ABSKexamplekey"}, 0o644)
	UseClusterCredentialDir(dir)
	got, source, err := ResolveServiceCredential("bedrock", "")
	if err != nil || string(got) != "ABSKexamplekey" || source != CredentialFromCluster {
		t.Fatalf("cluster credential: %q %q %v", got, source, err)
	}
	if _, _, err := ResolveServiceCredential("openai", ""); !errors.Is(err, ErrNoServiceCredential) {
		t.Fatalf("a key the Secret does not hold: %v, want ErrNoServiceCredential", err)
	}
	// A link out of the volume is refused, not followed.
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveServiceCredential("escape", ""); err == nil || errors.Is(err, ErrNoServiceCredential) {
		t.Fatalf("a link out of the Secret volume was accepted: %v", err)
	}
	// A key a group or other account can write is refused.
	writable := clusterSecretVolume(t, map[string]string{"bedrock": "k"}, 0o666)
	UseClusterCredentialDir(writable)
	if _, _, err := ResolveServiceCredential("bedrock", ""); err == nil || errors.Is(err, ErrNoServiceCredential) {
		t.Fatalf("a writable cluster credential was accepted: %v", err)
	}
	// Without a cluster directory nothing changes: no key.
	UseClusterCredentialDir("")
	if _, _, err := ResolveServiceCredential("bedrock", ""); !errors.Is(err, ErrNoServiceCredential) {
		t.Fatalf("no cluster directory: %v, want ErrNoServiceCredential", err)
	}
}
