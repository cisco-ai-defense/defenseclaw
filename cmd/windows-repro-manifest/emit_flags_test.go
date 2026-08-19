// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestEmitManifestUnsignedFlag exercises the --unsigned flag added by
// docs/specs/002-windows-avc-packaging. It asserts that:
//   - the emitted manifest.json carries `"unsigned": true`,
//   - the default distribution_flavor is auto-suffixed with "-unsigned",
//   - an explicit --distribution-flavor is NOT auto-suffixed (the
//     caller is trusted to have shaped the string).
//
// The round-trip integration test in Stage 5's CI job drives assemble.sh
// end-to-end; this Go-level test locks the emitter-side flag behavior
// so a regression there is caught without needing a live CI runner.
func TestEmitManifestUnsignedFlag(t *testing.T) {
	// Build a tiny payload dir with a single file so hashPayloadDir
	// has something to hash.
	payloadDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(payloadDir, "defenseclaw.exe"), []byte("fixture"), 0o644); err != nil {
		t.Fatalf("stage payload: %v", err)
	}
	outDir := t.TempDir()

	// Default distribution flavor + --unsigned → auto-suffix.
	manifest := filepath.Join(outDir, "auto.json")
	err := runEmitManifest([]string{
		"--version", "0.9.0",
		"--source-commit", "1111222233334444555566667777888899990000",
		"--payload-dir", payloadDir,
		"--out", manifest,
		"--unsigned",
	})
	if err != nil {
		t.Fatalf("emit-manifest default+unsigned: %v", err)
	}
	doc := readJSONFile(t, manifest)
	if got := doc["unsigned"]; got != true {
		t.Fatalf("unsigned=%v, want true", got)
	}
	if got := doc["distribution_flavor"]; got != "managed-enterprise-unsigned" {
		t.Fatalf("distribution_flavor=%q, want %q", got, "managed-enterprise-unsigned")
	}

	// Explicit distribution flavor + --unsigned → NO auto-suffix.
	explicit := filepath.Join(outDir, "explicit.json")
	err = runEmitManifest([]string{
		"--version", "0.9.0",
		"--source-commit", "1111222233334444555566667777888899990000",
		"--payload-dir", payloadDir,
		"--out", explicit,
		"--distribution-flavor", "downstream-test-flavor",
		"--unsigned",
	})
	if err != nil {
		t.Fatalf("emit-manifest explicit+unsigned: %v", err)
	}
	doc = readJSONFile(t, explicit)
	if got := doc["distribution_flavor"]; got != "downstream-test-flavor" {
		t.Fatalf("explicit distribution_flavor=%q, want %q", got, "downstream-test-flavor")
	}

	// Explicit --distribution-flavor with the same VALUE as the default
	// ("managed-enterprise") + --unsigned → NO auto-suffix. Guards
	// against the regression a value-vs-default comparison would
	// cause: the caller asked for `managed-enterprise` explicitly, so
	// return `managed-enterprise` even under --unsigned. See CR
	// spec-002:PRRT_kwDORuAK-s6ahAB9.
	explicitDefault := filepath.Join(outDir, "explicit-default.json")
	err = runEmitManifest([]string{
		"--version", "0.9.0",
		"--source-commit", "1111222233334444555566667777888899990000",
		"--payload-dir", payloadDir,
		"--out", explicitDefault,
		"--distribution-flavor", "managed-enterprise",
		"--unsigned",
	})
	if err != nil {
		t.Fatalf("emit-manifest explicit-default+unsigned: %v", err)
	}
	doc = readJSONFile(t, explicitDefault)
	if got := doc["distribution_flavor"]; got != "managed-enterprise" {
		t.Fatalf("explicit default + unsigned: distribution_flavor=%q, want %q (must NOT be auto-suffixed when the caller explicitly passed the default value)", got, "managed-enterprise")
	}
	if got := doc["unsigned"]; got != true {
		t.Fatalf("explicit default + unsigned: unsigned=%v, want true", got)
	}

	// No --unsigned → unsigned=false, default flavor unchanged.
	signed := filepath.Join(outDir, "signed.json")
	err = runEmitManifest([]string{
		"--version", "0.9.0",
		"--source-commit", "1111222233334444555566667777888899990000",
		"--payload-dir", payloadDir,
		"--out", signed,
	})
	if err != nil {
		t.Fatalf("emit-manifest default: %v", err)
	}
	doc = readJSONFile(t, signed)
	if got := doc["unsigned"]; got != false {
		t.Fatalf("default unsigned=%v, want false", got)
	}
	if got := doc["distribution_flavor"]; got != "managed-enterprise" {
		t.Fatalf("default distribution_flavor=%q, want %q", got, "managed-enterprise")
	}
}

// TestEmitProvenancePlaceholder locks in the --setup-sha256-placeholder
// contract added by docs/specs/002-windows-avc-packaging. In placeholder
// mode:
//   - setup_sha256 is the empty string,
//   - setup_size is 0,
//   - --setup-exe is optional (in this test we skip it),
//   - --unsigned still stamps unsigned=true and auto-suffixes the flavor.
//
// The signed EXE hash is populated by AVC (or the optional
// finalize.{sh,ps1}) after step-3 signtool sign — see
// design.md § Decisions for the rationale.
func TestEmitProvenancePlaceholder(t *testing.T) {
	outDir := t.TempDir()

	prov := filepath.Join(outDir, "prov.json")
	err := runEmitProvenance([]string{
		"--version", "0.9.0",
		"--source-commit", "1111222233334444555566667777888899990000",
		"--out", prov,
		"--setup-sha256-placeholder",
		"--unsigned",
	})
	if err != nil {
		t.Fatalf("emit-provenance placeholder+unsigned: %v", err)
	}
	doc := readJSONFile(t, prov)
	if got := doc["setup_sha256"]; got != "" {
		t.Fatalf("setup_sha256=%q, want empty", got)
	}
	// json.Unmarshal into map[string]any gives numbers as float64.
	if got, _ := doc["setup_size"].(float64); got != 0 {
		t.Fatalf("setup_size=%v, want 0", doc["setup_size"])
	}
	if got := doc["unsigned"]; got != true {
		t.Fatalf("unsigned=%v, want true", got)
	}
	if got := doc["distribution_flavor"]; got != "managed-enterprise-unsigned" {
		t.Fatalf("distribution_flavor=%q, want %q", got, "managed-enterprise-unsigned")
	}
}

// TestEmitProvenancePlaceholderSkipsExeCheck verifies that placeholder
// mode does NOT require --setup-exe. This is the whole point of the
// flag: at emit time, the signed EXE does not exist yet.
func TestEmitProvenancePlaceholderSkipsExeCheck(t *testing.T) {
	outDir := t.TempDir()
	prov := filepath.Join(outDir, "prov.json")

	// No --setup-exe. Would fail requireFlags in the default path.
	err := runEmitProvenance([]string{
		"--version", "0.9.0",
		"--source-commit", "1111222233334444555566667777888899990000",
		"--out", prov,
		"--setup-sha256-placeholder",
	})
	if err != nil {
		t.Fatalf("emit-provenance placeholder without --setup-exe: %v", err)
	}
	// Sanity: the file was written.
	if _, err := os.Stat(prov); err != nil {
		t.Fatalf("provenance.json missing: %v", err)
	}
}

// TestEmitProvenanceDefaultRequiresSetupExe verifies the pre-existing
// contract still holds: without --setup-sha256-placeholder, --setup-exe
// is required. Guards against a future refactor that accidentally makes
// setup-exe optional in the hash-computing path.
func TestEmitProvenanceDefaultRequiresSetupExe(t *testing.T) {
	outDir := t.TempDir()
	prov := filepath.Join(outDir, "prov.json")

	err := runEmitProvenance([]string{
		"--version", "0.9.0",
		"--source-commit", "1111222233334444555566667777888899990000",
		"--out", prov,
	})
	if err == nil {
		t.Fatalf("emit-provenance without --setup-exe or placeholder should have errored")
	}
}

func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return doc
}
