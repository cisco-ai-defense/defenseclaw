// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadManifestWithSHA256BindsExactParsedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	data := []byte("version: 1\ntargets:\n  - user: alice\n    connector: codex\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, digest, err := LoadManifestWithSHA256(path)
	if err != nil {
		t.Fatalf("LoadManifestWithSHA256: %v", err)
	}
	want := sha256.Sum256(data)
	if digest != hex.EncodeToString(want[:]) {
		t.Fatalf("digest = %q, want exact-byte digest %x", digest, want)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].Connector != "codex" {
		t.Fatalf("manifest = %+v, want parsed Codex target", manifest)
	}
}

func TestLoadManifestRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	data := []byte("version: 1\ntargets:\n  - user: alice\n    connector: codex\n    enabld: false\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "field enabld not found") {
		t.Fatalf("LoadManifest error = %v, want unknown-field rejection", err)
	}
}

func TestLoadManifestRejectsTrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	data := []byte("version: 1\ntargets: []\n---\nversion: 1\ntargets: []\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("LoadManifest error = %v, want trailing-document rejection", err)
	}
}

func TestLoadManifestAcceptsEmptyDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte("# no managed targets yet\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if manifest.Version != 1 || len(manifest.Targets) != 0 {
		t.Fatalf("manifest = %+v, want version 1 with no targets", manifest)
	}
}

func TestLoadManifestRejectsSparseOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(enterpriseHookManifestMaxBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadManifest oversized error = %v, want bounded refusal", err)
	}
}
