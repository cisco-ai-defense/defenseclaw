// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

func TestClaudeReleaseManifestSignatureAndPlatformChecksum(t *testing.T) {
	manifest, err := os.ReadFile(filepath.Join("testdata", "claude-2.1.270-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(filepath.Join("testdata", "claude-2.1.270-manifest.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if checksums, ok := parseClaudeReleaseManifest(manifest, signature, "2.1.270"); !ok || len(checksums) == 0 {
		t.Fatal("signed platform checksums were not accepted")
	}
	modified := bytes.Clone(manifest)
	modified = append(modified, ' ')
	if _, ok := parseClaudeReleaseManifest(modified, signature, "2.1.270"); ok {
		t.Fatal("changed manifest was accepted")
	}
	if _, ok := parseClaudeReleaseManifest(manifest, signature, "2.1.271"); ok {
		t.Fatal("different version was accepted")
	}
	if _, ok := parseClaudeReleaseManifest(manifest, signature[:len(signature)/2], "2.1.270"); ok {
		t.Fatal("incomplete signature was accepted")
	}
}

func TestClaudeReleaseVersionValidation(t *testing.T) {
	for _, version := range []string{"", "2.1", "2.1.1/manifest.json", "2.1.1x", "2.1.123456789", "2..1", "2.1.1.", ".2.1"} {
		if plane.IsClaudeReleaseVersion(version) {
			t.Errorf("unexpected release version %q", version)
		}
	}
	if !plane.IsClaudeReleaseVersion("2.1.317") {
		t.Fatal("ordinary release version was rejected")
	}
}
