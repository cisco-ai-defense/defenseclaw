// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestLoadOrCreateIdentityRefusesIndirectDataDirWithoutOutsideMutation(t *testing.T) {
	aliasRoot := testenv.PrivateTempDir(t)
	outside := testenv.PrivateTempDir(t)
	managed := filepath.Join(outside, "outer", "managed")
	if err := os.MkdirAll(managed, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(managed, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	jump := filepath.Join(aliasRoot, "jump")
	if err := os.Symlink(outside, jump); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	dataDir := filepath.Join(jump, "outer", "managed")
	keyFile := filepath.Join(dataDir, "deeper", "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
		t.Fatal("LoadOrCreateIdentity accepted an indirect data directory")
	}
	for _, path := range []string{
		filepath.Join(managed, "deeper"),
		filepath.Join(managed, deviceProvenanceSecretName),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("indirect identity path mutated outside tree: %s: %v", path, err)
		}
	}
}

func TestLoadOrCreateIdentityStillLoadsExistingKeyThroughIndirectDataDir(t *testing.T) {
	aliasRoot := testenv.PrivateTempDir(t)
	outside := testenv.PrivateTempDir(t)
	managed := filepath.Join(outside, "outer", "managed")
	if err := os.MkdirAll(managed, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	jump := filepath.Join(aliasRoot, "jump")
	if err := os.Symlink(outside, jump); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	realKey := filepath.Join(managed, "device.key")
	writeLegacyDeviceKey(t, realKey)
	indirectDataDir := filepath.Join(jump, "outer", "managed")
	indirectKey := filepath.Join(indirectDataDir, "device.key")

	if _, err := LoadOrCreateIdentity(indirectKey, indirectDataDir); err != nil {
		t.Fatalf("existing indirect key should remain load-only compatible: %v", err)
	}
	for _, path := range []string{
		filepath.Join(managed, deviceProvenanceSecretName),
		realKey + ".provenance",
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("existing indirect key was blessed: %s: %v", path, err)
		}
	}
}

func TestLoadOrCreateIdentityRefusesForeignOwnedDataDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing directory ownership requires root")
	}
	dataDir := testenv.PrivateTempDir(t)
	t.Cleanup(func() { _ = os.Chown(dataDir, os.Geteuid(), -1) })
	if err := os.Chown(dataDir, 65534, -1); err != nil {
		t.Skipf("cannot create foreign-owner fixture: %v", err)
	}
	keyFile := filepath.Join(dataDir, "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
		t.Fatal("LoadOrCreateIdentity accepted a foreign-owned data directory")
	}
	if _, err := os.Lstat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("identity was published under a foreign-owned data directory: %v", err)
	}
}
