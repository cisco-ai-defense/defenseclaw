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
	// Pass -AllowUnsigned to bypass the SigningType/ExpectedSignerSha256
	// required-flag gate. The test targets the SourceCommit-pattern
	// check specifically, which fires after required-flag validation.
	_, err := parseFlags([]string{
		"-PayloadDir", "/tmp/payload",
		"-SetupExeUnsigned", "/tmp/setup.exe",
		"-SourceCommit", "not-a-sha",
		"-Version", "0.8.6",
		"-Out", "/tmp/out",
		"-AllowUnsigned",
	})
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("expected *usageError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "SourceCommit") {
		t.Errorf("error should call out SourceCommit; got: %s", err)
	}
}

func TestInvalidVersion(t *testing.T) {
	// Same rationale as TestInvalidSourceCommit — bypass the sig-policy
	// gate so the Version-pattern check is what we hit.
	_, err := parseFlags([]string{
		"-PayloadDir", "/tmp/payload",
		"-SetupExeUnsigned", "/tmp/setup.exe",
		"-SourceCommit", "0123456789abcdef0123456789abcdef01234567",
		"-Version", "not-semver",
		"-Out", "/tmp/out",
		"-AllowUnsigned",
	})
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("expected *usageError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "Version") {
		t.Errorf("error should call out Version; got: %s", err)
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

// validThumbprint is a 64-char hex SHA-256 fixture used by every
// classifier / flag test that needs the "expected" fingerprint. Not a
// real signer thumbprint — just something that passes normalizeThumbprint.
const validThumbprint = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

// TestNormalizeThumbprint covers the input-shape tolerance CodeRabbit
// asked for during design review: bare hex, colon-separated, spaced,
// uppercase — all should normalize to the same lowercase-no-separators
// canonical form. Anything not 64 hex bytes must fail.
func TestNormalizeThumbprint(t *testing.T) {
	canonical := validThumbprint

	ok := []struct {
		name  string
		input string
	}{
		{"bare-hex-lower", canonical},
		{"bare-hex-upper", strings.ToUpper(canonical)},
		{"colon-separated-upper", "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"},
		{"space-separated-upper", "AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99"},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeThumbprint(tc.input)
			if err != nil {
				t.Fatalf("normalizeThumbprint(%q): %v", tc.input, err)
			}
			if got != canonical {
				t.Errorf("normalizeThumbprint(%q) = %q, want %q", tc.input, got, canonical)
			}
		})
	}

	bad := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"short", "aabbcc"},
		{"non-hex", "zzzz" + strings.Repeat("a", 60)},
		{"long", canonical + "aa"},
		{"one-char-off", canonical + "z"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := normalizeThumbprint(tc.input); err == nil {
				t.Errorf("normalizeThumbprint(%q) unexpectedly succeeded", tc.input)
			}
		})
	}
}

func TestParseSigningType(t *testing.T) {
	prod := []string{"PROD", "prod", "Prod", " PROD ", "\tPROD\n"}
	dev := []string{"DEV", "dev", "Dev", " DEV "}
	bad := []string{"", "PRODUCTION", "release", "test", "DEV,PROD"}

	for _, s := range prod {
		st, err := parseSigningType(s)
		if err != nil {
			t.Errorf("parseSigningType(%q): %v", s, err)
			continue
		}
		if st != signingTypeProd {
			t.Errorf("parseSigningType(%q) = %v, want signingTypeProd", s, st)
		}
	}
	for _, s := range dev {
		st, err := parseSigningType(s)
		if err != nil {
			t.Errorf("parseSigningType(%q): %v", s, err)
			continue
		}
		if st != signingTypeDev {
			t.Errorf("parseSigningType(%q) = %v, want signingTypeDev", s, st)
		}
	}
	for _, s := range bad {
		if _, err := parseSigningType(s); err == nil {
			t.Errorf("parseSigningType(%q) unexpectedly succeeded", s)
		}
	}

	// String() round-trip.
	if signingTypeProd.String() != "PROD" || signingTypeDev.String() != "DEV" {
		t.Errorf("signingType.String() incorrect: PROD=%q DEV=%q",
			signingTypeProd.String(), signingTypeDev.String())
	}
}

// TestClassifyVerify walks the trust matrix documented in
// signature.go. Pure function, no exec / Windows dependency —
// synthetic psSignatureRecord tuples exercise every accept / reject
// branch. This is the primary safety net for the DEV / PROD contract
// AVC handoff v2 pinned.
func TestClassifyVerify(t *testing.T) {
	cases := []struct {
		name       string
		sigType    signingType
		fp         string
		rec        psSignatureRecord
		wantAccept bool
		// wantErrType: only checked when wantAccept is false.
		wantErrType func(error) bool
	}{
		// ---------------- accept-in-both ----------------
		{
			name:       "prod-valid-fp-match",
			sigType:    signingTypeProd,
			fp:         validThumbprint,
			rec:        psSignatureRecord{Status: "Valid", Thumbprint: validThumbprint, ChainStatusFlags: []string{"NoError"}},
			wantAccept: true,
		},
		{
			name:       "dev-valid-fp-match",
			sigType:    signingTypeDev,
			fp:         validThumbprint,
			rec:        psSignatureRecord{Status: "Valid", Thumbprint: validThumbprint, ChainStatusFlags: []string{"NoError"}},
			wantAccept: true,
		},

		// ---------------- fp checks (fatal regardless of mode) ----------------
		{
			name:    "missing-signer-cert",
			sigType: signingTypeProd,
			fp:      validThumbprint,
			rec:     psSignatureRecord{Status: "NotSigned", Thumbprint: ""},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "fp-mismatch-even-if-status-valid",
			sigType: signingTypeProd,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:     "Valid",
				Thumbprint: strings.Repeat("11", 32),
			},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "fp-mismatch-in-dev-cert-e-chaining",
			sigType: signingTypeDev,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:             "UnknownError",
				Thumbprint:         strings.Repeat("22", 32),
				ChainStatusFlags:   []string{"PartialChain"},
				CertEChainingMatch: true,
			},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},

		// ---------------- PROD status gate ----------------
		{
			name:    "prod-unknown-error-even-with-cert-e-chaining",
			sigType: signingTypeProd,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:             "UnknownError",
				Thumbprint:         validThumbprint,
				ChainStatusFlags:   []string{"PartialChain"},
				CertEChainingMatch: true,
			},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "prod-not-trusted",
			sigType: signingTypeProd,
			fp:      validThumbprint,
			rec:     psSignatureRecord{Status: "NotTrusted", Thumbprint: validThumbprint},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "prod-hash-mismatch",
			sigType: signingTypeProd,
			fp:      validThumbprint,
			rec:     psSignatureRecord{Status: "HashMismatch", Thumbprint: validThumbprint},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},

		// ---------------- DEV: accept CERT_E_CHAINING only ----------------
		{
			name:    "dev-unknown-error-cert-e-chaining-with-partial-chain",
			sigType: signingTypeDev,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:             "UnknownError",
				StatusMessage:      "A certificate chain could not be built to a trusted root authority.",
				Thumbprint:         validThumbprint,
				ChainStatusFlags:   []string{"PartialChain"},
				CertEChainingMatch: true,
			},
			wantAccept: true,
		},
		{
			name:    "dev-unknown-error-without-cert-e-chaining-message",
			sigType: signingTypeDev,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:             "UnknownError",
				StatusMessage:      "The revocation function was unable to check revocation for the certificate.",
				Thumbprint:         validThumbprint,
				ChainStatusFlags:   []string{"PartialChain"},
				CertEChainingMatch: false,
			},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "dev-cert-e-chaining-but-chain-has-revoked-flag",
			sigType: signingTypeDev,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:             "UnknownError",
				Thumbprint:         validThumbprint,
				ChainStatusFlags:   []string{"PartialChain", "Revoked"},
				CertEChainingMatch: true,
			},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "dev-cert-e-chaining-but-chain-shows-not-time-valid",
			sigType: signingTypeDev,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:             "UnknownError",
				Thumbprint:         validThumbprint,
				ChainStatusFlags:   []string{"NotTimeValid"},
				CertEChainingMatch: true,
			},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "dev-not-trusted-status-rejected",
			sigType: signingTypeDev,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:             "NotTrusted",
				Thumbprint:         validThumbprint,
				ChainStatusFlags:   []string{"PartialChain"},
				CertEChainingMatch: false,
			},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "dev-hash-mismatch-still-fatal",
			sigType: signingTypeDev,
			fp:      validThumbprint,
			rec:     psSignatureRecord{Status: "HashMismatch", Thumbprint: validThumbprint},
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
		{
			name:    "dev-cert-e-chaining-flag-with-only-noerror",
			sigType: signingTypeDev,
			fp:      validThumbprint,
			rec: psSignatureRecord{
				Status:             "UnknownError",
				Thumbprint:         validThumbprint,
				ChainStatusFlags:   []string{"NoError"},
				CertEChainingMatch: true,
			},
			// NoError alone means the chain built cleanly — but status
			// says UnknownError. Something's inconsistent; reject.
			wantErrType: func(err error) bool {
				_, ok := err.(*signatureError)
				return ok
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyVerify("payload/x.exe", tc.sigType, tc.fp, tc.rec)
			if tc.wantAccept {
				if err != nil {
					t.Errorf("expected accept, got %T: %v", err, err)
				}
				return
			}
			if err == nil {
				t.Errorf("expected reject, got nil")
				return
			}
			if tc.wantErrType != nil && !tc.wantErrType(err) {
				t.Errorf("expected specific error type, got %T: %v", err, err)
			}
		})
	}
}

// TestChainStatusIsOnlyPartialChain is a direct fixture for the fail-
// closed helper — most cases are already covered by TestClassifyVerify,
// but a couple of edge cases (empty slice, all-NoError) are cleaner as
// standalone assertions.
func TestChainStatusIsOnlyPartialChain(t *testing.T) {
	ok := [][]string{
		{"PartialChain"},
		{"PartialChain", "NoError"},
		{"NoError", "PartialChain"},
		{"PartialChain", ""},
	}
	bad := [][]string{
		{},                               // no chain built at all
		{"NoError"},                      // clean chain — not the DEV shape
		{""},                             // stray empty
		{"NotTimeValid"},                 // expired
		{"Revoked"},                      // revoked
		{"PartialChain", "NotTimeValid"}, // co-occurring flag
		{"PartialChain", "Revoked"},      // co-occurring flag
		{"UntrustedRoot"},                // untrusted root — different HR
		{"OfflineRevocation"},            // CRL/OCSP offline
		{"PartialChain", "OfflineRevocation"},
	}
	for _, flags := range ok {
		if !chainStatusIsOnlyPartialChain(flags) {
			t.Errorf("chainStatusIsOnlyPartialChain(%v) = false, want true", flags)
		}
	}
	for _, flags := range bad {
		if chainStatusIsOnlyPartialChain(flags) {
			t.Errorf("chainStatusIsOnlyPartialChain(%v) = true, want false", flags)
		}
	}
}

// TestParseFlagsSigningPolicy pins the CLI mutual-exclusion + validation
// contract. The three permitted shapes are: (a) -AllowUnsigned alone,
// (b) -SigningType + -ExpectedSignerSha256, (c) neither (error).
func TestParseFlagsSigningPolicy(t *testing.T) {
	baseArgs := []string{
		"-PayloadDir", "/tmp/payload",
		"-SetupExeUnsigned", "/tmp/setup.exe",
		"-SourceCommit", "0123456789abcdef0123456789abcdef01234567",
		"-Version", "0.8.6",
		"-Out", "/tmp/out",
	}
	withArgs := func(extra ...string) []string {
		return append(append([]string(nil), baseArgs...), extra...)
	}

	// (a) -AllowUnsigned alone is fine.
	if _, err := parseFlags(withArgs("-AllowUnsigned")); err != nil {
		t.Errorf("-AllowUnsigned alone: %v", err)
	}

	// (b) -SigningType + -ExpectedSignerSha256 is fine.
	opts, err := parseFlags(withArgs("-SigningType", "PROD", "-ExpectedSignerSha256", validThumbprint))
	if err != nil {
		t.Fatalf("prod + fingerprint: %v", err)
	}
	if opts.signingTypeParsed != signingTypeProd {
		t.Errorf("signingTypeParsed = %v, want PROD", opts.signingTypeParsed)
	}
	if opts.expectedThumbprint != validThumbprint {
		t.Errorf("expectedThumbprint = %q, want %q", opts.expectedThumbprint, validThumbprint)
	}

	// DEV also works.
	opts, err = parseFlags(withArgs("-SigningType", "DEV", "-ExpectedSignerSha256", validThumbprint))
	if err != nil {
		t.Fatalf("dev + fingerprint: %v", err)
	}
	if opts.signingTypeParsed != signingTypeDev {
		t.Errorf("signingTypeParsed = %v, want DEV", opts.signingTypeParsed)
	}

	// (c) missing SigningType/Fingerprint without AllowUnsigned fails.
	_, err = parseFlags(baseArgs)
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("missing sig-policy flags: expected *usageError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "SigningType") || !strings.Contains(err.Error(), "ExpectedSignerSha256") {
		t.Errorf("error should call out both missing flags; got: %s", err)
	}

	// Mutual exclusion: -AllowUnsigned with either sig-policy flag fails.
	_, err = parseFlags(withArgs("-AllowUnsigned", "-SigningType", "PROD"))
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("AllowUnsigned + SigningType: expected *usageError, got %T: %v", err, err)
	}
	_, err = parseFlags(withArgs("-AllowUnsigned", "-ExpectedSignerSha256", validThumbprint))
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("AllowUnsigned + ExpectedSignerSha256: expected *usageError, got %T: %v", err, err)
	}

	// Malformed SigningType fails.
	_, err = parseFlags(withArgs("-SigningType", "RELEASE", "-ExpectedSignerSha256", validThumbprint))
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("bad SigningType: expected *usageError, got %T: %v", err, err)
	}

	// Malformed fingerprint fails.
	_, err = parseFlags(withArgs("-SigningType", "PROD", "-ExpectedSignerSha256", "not-hex"))
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("bad fingerprint: expected *usageError, got %T: %v", err, err)
	}
}
