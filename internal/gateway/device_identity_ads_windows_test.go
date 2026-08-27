// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestDeviceIdentityPathSyntaxWindowsPreservesVolumePrefixes(t *testing.T) {
	for _, path := range []string{
		`C:\DefenseClaw\device.key`,
		`\\server\share\DefenseClaw\device.key`,
		`\\?\C:\DefenseClaw\device.key`,
		`\\?\UNC\server\share\DefenseClaw\device.key`,
		`\\?\Volume{12345678-1234-1234-1234-123456789abc}\DefenseClaw\device.key`,
	} {
		t.Run(path, func(t *testing.T) {
			if err := validateDeviceIdentityPathSyntax(path, filepath.Dir(path)); err != nil {
				t.Fatalf("ordinary Windows volume path rejected: %v", err)
			}
		})
	}
}

func TestDeviceIdentityPathSyntaxWindowsRejectsPostVolumeColons(t *testing.T) {
	for _, fixture := range []struct {
		target  string
		dataDir string
	}{
		{target: `C:\DefenseClaw\device.key:stream`, dataDir: `C:\DefenseClaw`},
		{target: `C:\DefenseClaw\device.provenance.secret:KEY`, dataDir: `C:\DefenseClaw`},
		{target: `C:\DefenseClaw:identity\device.key`, dataDir: `C:\DefenseClaw:identity`},
		{target: `\\server\share\DefenseClaw\device.key:stream`, dataDir: `\\server\share\DefenseClaw`},
		{target: `\\?\C:\DefenseClaw\device.key:stream`, dataDir: `\\?\C:\DefenseClaw`},
	} {
		if err := validateDeviceIdentityPathSyntax(fixture.target, fixture.dataDir); err == nil {
			t.Fatalf("alternate data stream path was accepted: %q", fixture.target)
		}
	}
}

func TestLoadOrCreateIdentityWindowsRejectsADSWithoutPublication(t *testing.T) {
	for _, relativeTarget := range []string{
		"device.key:stream",
		"device.provenance.secret:key",
		"DEVICE.PROVENANCE.SECRET:KEY",
		filepath.Join("missing", "nested", "device.key:stream"),
	} {
		t.Run(relativeTarget, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			target := filepath.Join(dataDir, relativeTarget)

			_, err := LoadOrCreateIdentity(target, dataDir)
			if err == nil || !strings.Contains(err.Error(), "alternate data streams") {
				t.Fatalf("LoadOrCreateIdentity error = %v, want ADS refusal", err)
			}
			for _, path := range []string{
				filepath.Join(dataDir, "device.key"),
				filepath.Join(dataDir, deviceProvenanceSecretName),
				filepath.Join(dataDir, "device.key.provenance"),
				filepath.Join(dataDir, "missing"),
			} {
				if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
					t.Fatalf("ADS refusal left filesystem residue at %s: %v", path, statErr)
				}
			}
		})
	}
}

func TestLoadOrCreateIdentityWindowsRejectsADSDataDirWithoutMutation(t *testing.T) {
	base := testenv.PrivateTempDir(t)
	dataDir := base + ":identity"
	target := filepath.Join(dataDir, "device.key")

	if _, err := LoadOrCreateIdentity(target, dataDir); err == nil ||
		!strings.Contains(err.Error(), "alternate data streams") {
		t.Fatalf("LoadOrCreateIdentity error = %v, want ADS refusal", err)
	}
	for _, path := range []string{
		filepath.Join(base, "device.key"),
		filepath.Join(base, deviceProvenanceSecretName),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("ADS data directory refusal mutated base directory: %s: %v", path, err)
		}
	}
}

func TestLoadOrCreateIdentityWindowsRejectsExistingADSBeforeRead(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	base := filepath.Join(dataDir, "existing-holder")
	if err := os.WriteFile(base, []byte("base-preserved"), 0o600); err != nil {
		t.Fatalf("WriteFile base: %v", err)
	}
	stream := base + ":device-key"
	writeLegacyDeviceKey(t, stream)

	if _, err := LoadOrCreateIdentity(stream, dataDir); err == nil ||
		!strings.Contains(err.Error(), "alternate data streams") {
		t.Fatalf("LoadOrCreateIdentity error = %v, want ADS refusal", err)
	}
	data, err := os.ReadFile(base)
	if err != nil || string(data) != "base-preserved" {
		t.Fatalf("base file changed: data=%q err=%v", data, err)
	}
	if _, err := os.Lstat(stream + ".provenance"); !os.IsNotExist(err) {
		t.Fatalf("existing ADS identity was blessed: %v", err)
	}
}
