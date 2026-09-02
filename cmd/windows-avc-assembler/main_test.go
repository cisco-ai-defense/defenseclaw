// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
)

// stagePayloadDir writes the six required payload files with unique
// per-file contents so hash mismatches surface as different digests
// rather than accidental collisions.
func stagePayloadDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for i, name := range requiredPayloadFiles {
		// Distinct per-file content so any mix-up in trailer order
		// shows up as a hash / content mismatch, not a false positive.
		body := []byte("payload-" + name + "-" + string(rune('a'+i)))
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// stagePrebuiltSetup writes a fake prebuilt Setup EXE (arbitrary
// bytes). We only need the bytes to be non-empty and free of a
// trailer; the assembler's Authenticode verify is skipped via
// -AllowUnsigned in every unit test.
func stagePrebuiltSetup(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "DefenseClawSetup-Enterprise-x64.exe.unsigned")
	body := []byte("prebuilt PE bytes (test fixture); real EXE is Go-compiled\n")
	body = append(body, bytes.Repeat([]byte{0x77}, 2048)...) // some volume
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write prebuilt: %v", err)
	}
	return path
}

// baseOpts returns a validated options set with -AllowUnsigned so
// tests do not depend on signtool availability. Override individual
// fields per-test.
func baseOpts(t *testing.T) options {
	return options{
		PayloadDir:       stagePayloadDir(t),
		SetupExeUnsigned: stagePrebuiltSetup(t),
		SourceCommit:     "0123456789abcdef0123456789abcdef01234567",
		Version:          "0.8.6",
		Out:              filepath.Join(t.TempDir(), "out"),
		AllowUnsigned:    true,
	}
}

func TestAssembleHappyPath(t *testing.T) {
	opts := baseOpts(t)
	if err := assemble(opts, &bytes.Buffer{}); err != nil {
		t.Fatalf("assemble: %v", err)
	}
	assembled := filepath.Join(opts.Out, artifactName)
	prov := assembled + provenanceSuffix
	if _, err := os.Stat(assembled); err != nil {
		t.Errorf("expected assembled EXE at %s: %v", assembled, err)
	}
	if _, err := os.Stat(prov); err != nil {
		t.Errorf("expected provenance at %s: %v", prov, err)
	}

	// Round-trip the assembled EXE through the trailer reader — proves
	// the file the runtime would open on the tester's box is well-
	// formed and each payload file survives byte-identical.
	res, err := setuppayload.ReadFile(assembled)
	if err != nil {
		t.Fatalf("ReadFile trailer: %v", err)
	}
	if len(res.Entries) != len(requiredPayloadFiles) {
		t.Fatalf("entry count: got %d want %d", len(res.Entries), len(requiredPayloadFiles))
	}
	// Every declared payload file should extract byte-identical from
	// both the trailer archive and the input directory. Track which
	// required names have matched so a duplicate returned entry
	// (whose bytes happen to match) can't paper over a missing name
	// somewhere else in the set.
	remaining := make(map[string]struct{}, len(requiredPayloadFiles))
	for _, name := range requiredPayloadFiles {
		remaining[name] = struct{}{}
	}
	for _, e := range res.Entries {
		if _, expected := remaining[e.Name]; !expected {
			t.Errorf("trailer entry %q is not in requiredPayloadFiles (unexpected or duplicate)", e.Name)
			continue
		}
		delete(remaining, e.Name)
		disk, err := os.ReadFile(filepath.Join(opts.PayloadDir, e.Name))
		if err != nil {
			t.Errorf("read source %s: %v", e.Name, err)
			continue
		}
		if !bytes.Equal(disk, e.Contents) {
			t.Errorf("trailer contents for %s diverged from source", e.Name)
		}
	}
	if len(remaining) != 0 {
		t.Errorf("trailer missing required entries: %v", remaining)
	}

	// Manifest bytes inside the trailer must parse and carry the
	// version + source-commit we passed in.
	var manifest map[string]any
	if err := json.Unmarshal(res.Manifest, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if manifest["version"] != opts.Version {
		t.Errorf("manifest version: got %v want %s", manifest["version"], opts.Version)
	}
	if manifest["source_commit"] != opts.SourceCommit {
		t.Errorf("manifest source_commit: got %v want %s", manifest["source_commit"], opts.SourceCommit)
	}
	if manifest["distribution_flavor"] != distributionFlavorUnsigned {
		t.Errorf("manifest flavor: got %v want %s", manifest["distribution_flavor"], distributionFlavorUnsigned)
	}
}

// TestReproducibilityByteIdentical is the spec 001 REQ-07 gate at the
// full-assembler level: two runs against byte-identical inputs must
// produce a byte-identical output EXE.
func TestReproducibilityByteIdentical(t *testing.T) {
	optsA := baseOpts(t)
	optsB := baseOpts(t)
	// Copy every payload file from A into B so both runs see the same
	// bytes for each name (t.TempDir gives them distinct paths).
	for _, name := range requiredPayloadFiles {
		src, err := os.ReadFile(filepath.Join(optsA.PayloadDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(optsB.PayloadDir, name), src, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// Same for the prebuilt Setup EXE.
	prebuilt, err := os.ReadFile(optsA.SetupExeUnsigned)
	if err != nil {
		t.Fatalf("read prebuilt: %v", err)
	}
	if err := os.WriteFile(optsB.SetupExeUnsigned, prebuilt, 0o644); err != nil {
		t.Fatalf("write prebuilt B: %v", err)
	}

	if err := assemble(optsA, &bytes.Buffer{}); err != nil {
		t.Fatalf("assemble A: %v", err)
	}
	if err := assemble(optsB, &bytes.Buffer{}); err != nil {
		t.Fatalf("assemble B: %v", err)
	}
	shaA := sha256File(t, filepath.Join(optsA.Out, artifactName))
	shaB := sha256File(t, filepath.Join(optsB.Out, artifactName))
	if shaA != shaB {
		t.Fatalf("assembler not reproducible:\n  sha256(A) = %s\n  sha256(B) = %s", shaA, shaB)
	}
	// And provenance.json must also be byte-identical — same
	// deterministic marshaller. Check the read errors before comparing:
	// if the assembler failed to emit provenance in either run,
	// bytes.Equal(nil, nil) would trivially pass and swallow the bug.
	provA, err := os.ReadFile(filepath.Join(optsA.Out, artifactName+provenanceSuffix))
	if err != nil {
		t.Fatalf("read provenance A: %v", err)
	}
	provB, err := os.ReadFile(filepath.Join(optsB.Out, artifactName+provenanceSuffix))
	if err != nil {
		t.Fatalf("read provenance B: %v", err)
	}
	if !bytes.Equal(provA, provB) {
		t.Errorf("provenance.json diverged between runs")
	}
}

func TestMissingRequiredFlag(t *testing.T) {
	_, err := parseFlags([]string{"-Version", "0.8.6"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("expected *usageError, got %T", err)
	}
	if !strings.Contains(err.Error(), "PayloadDir") {
		t.Errorf("error should call out PayloadDir; got: %s", err)
	}
}

func TestInvalidSourceCommit(t *testing.T) {
	_, err := parseFlags([]string{
		"-PayloadDir", "/tmp/payload",
		"-SetupExeUnsigned", "/tmp/setup.exe",
		"-SourceCommit", "not-a-sha",
		"-Version", "0.8.6",
		"-Out", "/tmp/out",
	})
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("expected *usageError, got %T: %v", err, err)
	}
}

func TestInvalidVersion(t *testing.T) {
	_, err := parseFlags([]string{
		"-PayloadDir", "/tmp/payload",
		"-SetupExeUnsigned", "/tmp/setup.exe",
		"-SourceCommit", "0123456789abcdef0123456789abcdef01234567",
		"-Version", "not-semver",
		"-Out", "/tmp/out",
	})
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("expected *usageError, got %T: %v", err, err)
	}
}

func TestPayloadInventoryMissing(t *testing.T) {
	opts := baseOpts(t)
	// Remove one required file — assemble must refuse.
	if err := os.Remove(filepath.Join(opts.PayloadDir, "defenseclaw.exe")); err != nil {
		t.Fatalf("rm: %v", err)
	}
	err := assemble(opts, &bytes.Buffer{})
	if _, ok := err.(*ioError); !ok {
		t.Fatalf("expected *ioError, got %T: %v", err, err)
	}
}

func TestPayloadInventoryStray(t *testing.T) {
	opts := baseOpts(t)
	// Add a stray file — assemble must refuse.
	if err := os.WriteFile(filepath.Join(opts.PayloadDir, "unexpected.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write stray: %v", err)
	}
	err := assemble(opts, &bytes.Buffer{})
	if _, ok := err.(*ioError); !ok {
		t.Fatalf("expected *ioError, got %T: %v", err, err)
	}
}

func TestDoubleAppendRefused(t *testing.T) {
	opts := baseOpts(t)
	if err := assemble(opts, &bytes.Buffer{}); err != nil {
		t.Fatalf("first assemble: %v", err)
	}
	// Point the second run at the already-assembled EXE as its
	// prebuilt input — should refuse because a trailer is already
	// present.
	opts.SetupExeUnsigned = filepath.Join(opts.Out, artifactName)
	opts.Out = filepath.Join(t.TempDir(), "out2")
	err := assemble(opts, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected double-append refusal, got nil")
	}
	if _, ok := err.(*buildError); !ok {
		t.Fatalf("expected *buildError, got %T: %v", err, err)
	}
}

func TestSignatureVerifySkippedOnAllowUnsigned(t *testing.T) {
	// The happy-path test already runs with AllowUnsigned=true — this
	// case pins the inverse: WITHOUT AllowUnsigned, on non-Windows,
	// verify must fail with an ioError (the environment can't run
	// signtool). A signature rejection is a payload-side fault; a
	// missing runtime is an environment fault. Exit-code 4 is
	// reserved for the former, so this path returns ioError.
	//
	// runtime.GOOS is the correct host check — os.Getenv("GOOS") reads
	// only an env var that is unset by default, so a Windows CI runner
	// would fall through and try to run signtool on an unsigned test
	// fixture, tripping a signatureError that the assertion here would
	// misreport.
	if runtime.GOOS == "windows" {
		t.Skip("Windows host: signtool likely available; test asserts non-Windows behavior")
	}
	opts := baseOpts(t)
	opts.AllowUnsigned = false
	err := assemble(opts, &bytes.Buffer{})
	if _, ok := err.(*ioError); !ok {
		t.Fatalf("expected *ioError on non-Windows without -AllowUnsigned, got %T: %v", err, err)
	}
}

func TestExitCodeClassifier(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{&usageError{}, 2},
		{&signatureError{}, 4},
		{&buildError{}, 5},
		{&ioError{}, 6},
	}
	for _, tc := range cases {
		if got := classifyExitCode(tc.err); got != tc.code {
			t.Errorf("classifyExitCode(%T) = %d, want %d", tc.err, got, tc.code)
		}
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// TestAssertCNIsCisco pins the exact-equality contract that closes
// signtool's /n substring-match gap. A subject that CONTAINS the
// pinned CN but does not EQUAL it (e.g. an internal test cert) must
// be rejected — /n alone would let it through, so the follow-up
// exact check in verifyAuthenticode is the load-bearing gate.
func TestAssertCNIsCisco(t *testing.T) {
	exact := "Cisco Systems, Inc."
	if err := assertCNIsCisco("payload/x.exe", exact); err != nil {
		t.Errorf("exact CN unexpectedly rejected: %v", err)
	}
	rejects := []string{
		"Cisco Systems, Inc. (Test Root)",  // suffix — trailing junk
		"Not Cisco Systems, Inc.",          // prefix — masquerading
		"Cisco Systems, Inc",               // missing period — near-match
		"cisco systems, inc.",              // case difference — /n is case-insensitive but our contract is exact
		"Cisco Systems Inc.",               // missing comma
		"",                                 // empty
		" Cisco Systems, Inc. ",            // whitespace-padded
	}
	for _, cn := range rejects {
		err := assertCNIsCisco("payload/x.exe", cn)
		if err == nil {
			t.Errorf("subject %q was accepted, expected signatureError", cn)
			continue
		}
		if _, ok := err.(*signatureError); !ok {
			t.Errorf("subject %q rejected with %T; expected *signatureError", cn, err)
		}
	}
}
