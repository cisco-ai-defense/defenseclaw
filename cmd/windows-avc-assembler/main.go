// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Command windows-avc-assembler is the standalone Windows amd64
// binary AVC's signing pipeline runs to bind AVC-signed inner payload
// files onto the prebuilt outer DefenseClawSetup-Enterprise-x64.exe.
// It exists because AVC's CI does not provision Go: DefenseClaw
// prebuilds the outer EXE and this assembler, ships both in the AVC
// kit, and AVC's runner invokes this binary between its two
// `signtool sign` steps.
//
// Reproducibility gate: two runs against identical input must
// produce a byte-identical outer EXE (verified by
// TestReproducibilityByteIdentical in main_test.go).
//
// Exit codes match the shell assemble.sh contract this binary replaces:
//
//	0 — success
//	2 — invalid CLI args
//	4 — Cisco-signature assertion failed (non-AllowUnsigned only)
//	5 — trailer / build failure
//	6 — I/O error (missing input, permission denied, oversized)
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// artifactName is the standard filename the outer Setup EXE is
	// written as. Matches enterpriseSetupArtifactName in
	// cmd/defenseclaw-enterprise-setup/main.go.
	artifactName = "DefenseClawSetup-Enterprise-x64.exe"
	// provenanceSuffix is appended to the artifact name for the
	// provenance.json sidecar. Matches the assemble.sh output naming.
	provenanceSuffix = ".provenance.json"
)

// requiredPayloadFiles is the pinned inventory of files AVC signs.
// Any deviation (extra or missing file) is a hard failure — the
// runtime's identity gate refuses drift on either side.
//
// Kept in alphabetical order because the trailer archive sorts by name
// and this order is the one both the writer and the runtime observe.
// A change here MUST match cmd/defenseclaw-enterprise-setup/main.go
// requiredPayloadFiles verbatim.
var requiredPayloadFiles = []string{
	"DefenseClawEnterprise.psm1",
	"defenseclaw-cmid-broker.exe",
	"defenseclaw-gateway.exe",
	"defenseclaw-hook.exe",
	"defenseclaw.exe",
	"install-enterprise.ps1",
}

var sourceCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9_.-]+)?$`)

// options mirrors the PowerShell-style CLI grammar AVC prefers. Go's
// flag package parses `-PayloadDir value` and `-PayloadDir=value`
// interchangeably; single-dash long names are the Go default.
type options struct {
	PayloadDir       string
	SetupExeUnsigned string
	SourceCommit     string
	Version          string
	Out              string
	AllowUnsigned    bool
}

// usageError is emitted for CLI shape / value problems; the top-level
// exit shim maps it to exit code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// signatureError is emitted when Authenticode verify rejects an input;
// the top-level exit shim maps it to exit code 4.
type signatureError struct{ msg string }

func (e *signatureError) Error() string { return e.msg }

// ioError is emitted for anything filesystem-adjacent that we did not
// classify as a usage error; mapped to exit code 6.
type ioError struct{ msg string }

func (e *ioError) Error() string { return e.msg }

// buildError is emitted for trailer-append / assembly failures; mapped
// to exit code 5.
type buildError struct{ msg string }

func (e *buildError) Error() string { return e.msg }

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "DefenseClawAssembler: %s\n", err)
		os.Exit(classifyExitCode(err))
	}
}

// classifyExitCode maps typed error values to the exit-code contract
// documented in the file header. Any error the callee did not
// classify falls through to 6 (I/O — the widest catch-all matching
// assemble.sh).
func classifyExitCode(err error) int {
	switch err.(type) {
	case *usageError:
		return 2
	case *signatureError:
		return 4
	case *buildError:
		return 5
	case *ioError:
		return 6
	}
	return 6
}

func run(args []string, stdout, stderr io.Writer) error {
	opts, err := parseFlags(args)
	if err != nil {
		return err
	}
	return assemble(opts, stdout)
}

// parseFlags takes the raw args (os.Args[1:]) and returns validated
// options. Empty required fields, malformed values, and paths that do
// not resolve are surfaced here so the assemble() pipeline never has
// to defend against them.
func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("DefenseClawAssembler", flag.ContinueOnError)
	// Discard the flag package's own usage prints; we route errors
	// through the typed error map for a stable exit-code contract.
	fs.SetOutput(io.Discard)

	var opts options
	fs.StringVar(&opts.PayloadDir, "PayloadDir", "", "directory of AVC-signed inner files (required)")
	fs.StringVar(&opts.SetupExeUnsigned, "SetupExeUnsigned", "", "path to the prebuilt unsigned Setup EXE (required)")
	fs.StringVar(&opts.SourceCommit, "SourceCommit", "", "40-char lowercase git OID of the DefenseClaw source (required)")
	fs.StringVar(&opts.Version, "Version", "", "release semver, e.g. 0.8.6 (required)")
	fs.StringVar(&opts.Out, "Out", "", "output directory for the assembled EXE + provenance.json (required)")
	fs.BoolVar(&opts.AllowUnsigned, "AllowUnsigned", false, "skip Authenticode signature assertion; stamp unsigned=true in manifest+provenance")

	if err := fs.Parse(args); err != nil {
		return opts, &usageError{msg: err.Error()}
	}
	if fs.NArg() != 0 {
		return opts, &usageError{msg: fmt.Sprintf("unexpected positional argument %q", fs.Arg(0))}
	}

	// Cross-field validation — one error per required-empty field,
	// grouped for a single readable diagnostic. Matches the shell
	// assembler's pattern.
	var missing []string
	if strings.TrimSpace(opts.PayloadDir) == "" {
		missing = append(missing, "PayloadDir")
	}
	if strings.TrimSpace(opts.SetupExeUnsigned) == "" {
		missing = append(missing, "SetupExeUnsigned")
	}
	if strings.TrimSpace(opts.SourceCommit) == "" {
		missing = append(missing, "SourceCommit")
	}
	if strings.TrimSpace(opts.Version) == "" {
		missing = append(missing, "Version")
	}
	if strings.TrimSpace(opts.Out) == "" {
		missing = append(missing, "Out")
	}
	if len(missing) > 0 {
		return opts, &usageError{msg: fmt.Sprintf("missing required flag(s): -%s", strings.Join(missing, ", -"))}
	}
	if !sourceCommitPattern.MatchString(opts.SourceCommit) {
		return opts, &usageError{msg: fmt.Sprintf("-SourceCommit must be a 40-char lowercase git OID (got: %q)", opts.SourceCommit)}
	}
	if !versionPattern.MatchString(opts.Version) {
		return opts, &usageError{msg: fmt.Sprintf("-Version must be semver like 0.8.6 or 0.8.6-dev (got: %q)", opts.Version)}
	}
	return opts, nil
}

// assemble runs the six-stage flow that used to live in assemble.ps1 /
// assemble.sh, minus the Go build step (which now happens on the
// DefenseClaw build box before the kit is shipped) and minus the
// repro-flags preflight (the prebuilt EXE is already the reproducible
// artefact — the assembler only appends a trailer).
//
// Stages, one line each for the progress log AVC's CI shows:
//
//	1/5  verify inputs        — payload inventory, prebuilt EXE exists
//	2/5  verify signatures    — signtool verify /pa on every payload file
//	3/5  emit manifest        — SHA-256 every file, write manifest JSON
//	4/5  append trailer       — copy prebuilt EXE + append archive + manifest
//	5/5  emit provenance      — write provenance.json with placeholder sha256
//
// The prebuilt EXE is NOT modified in place — the assembler writes a
// fresh <Out>/DefenseClawSetup-Enterprise-x64.exe. AVC's signtool then
// signs THAT file; the trailer bytes fall inside Authenticode's hash
// range.
func assemble(opts options, stdout io.Writer) error {
	stage := func(n int, msg string) {
		fmt.Fprintf(stdout, "==> stage %d/5  %s\n", n, msg)
	}

	// Absolute-path the three user-supplied directories up front so a
	// downstream MkdirAll or file open never resolves the wrong tree
	// when we chdir (we do not chdir today, but the invariant is worth
	// preserving — see the same rule in assemble.sh's PAYLOAD_DIR
	// resolution block).
	payloadDir, err := filepath.Abs(opts.PayloadDir)
	if err != nil {
		return &ioError{msg: fmt.Sprintf("resolve -PayloadDir: %s", err)}
	}
	setupExe, err := filepath.Abs(opts.SetupExeUnsigned)
	if err != nil {
		return &ioError{msg: fmt.Sprintf("resolve -SetupExeUnsigned: %s", err)}
	}
	outDir, err := filepath.Abs(opts.Out)
	if err != nil {
		return &ioError{msg: fmt.Sprintf("resolve -Out: %s", err)}
	}
	if info, err := os.Stat(payloadDir); err != nil || !info.IsDir() {
		return &ioError{msg: fmt.Sprintf("-PayloadDir not a directory: %s", payloadDir)}
	}
	if info, err := os.Stat(setupExe); err != nil || info.IsDir() {
		return &ioError{msg: fmt.Sprintf("-SetupExeUnsigned not a file: %s", setupExe)}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return &ioError{msg: fmt.Sprintf("mkdir -Out: %s", err)}
	}

	fmt.Fprintf(stdout, "==> DefenseClawAssembler %s\n", opts.Version)
	fmt.Fprintf(stdout, "==> source-commit=%s allow-unsigned=%t\n",
		opts.SourceCommit[:12]+"...", opts.AllowUnsigned)

	// Stage 1: pinned inventory. A stray file or a missing required
	// name is a hard failure — silent trimming would let a malformed
	// kit slip past.
	stage(1, "verify inputs")
	if err := verifyPayloadInventory(payloadDir); err != nil {
		return err
	}

	// Stage 2: Authenticode verify. Skipped in -AllowUnsigned; the
	// runtime's hash gate then requires the unsigned certification
	// scope at install time (see platform_windows.go).
	stage(2, "verify signatures")
	if !opts.AllowUnsigned {
		for _, name := range requiredPayloadFiles {
			if err := verifyAuthenticode(filepath.Join(payloadDir, name)); err != nil {
				return err
			}
		}
	} else {
		fmt.Fprintln(stdout, "    -AllowUnsigned: skipping Authenticode verify")
	}

	// Stage 3: emit manifest JSON. Byte-stable — encoding/json sorts
	// keys, sha256 is deterministic, entries are sorted by name.
	stage(3, "emit manifest")
	manifestBytes, entries, err := buildManifestAndEntries(payloadDir, opts)
	if err != nil {
		return err
	}

	// Stage 4: append trailer to a fresh copy of the prebuilt EXE.
	// The assembled EXE lands at <Out>/DefenseClawSetup-Enterprise-x64.exe.
	stage(4, "append trailer")
	assembled := filepath.Join(outDir, artifactName)
	if err := appendTrailer(setupExe, assembled, entries, manifestBytes); err != nil {
		return err
	}

	// Stage 5: emit provenance.json with a placeholder setup_sha256.
	// The signed EXE hash is only knowable after AVC's step-3 signtool
	// sign; the finalize.ps1 helper (unchanged from spec 002) fills the
	// placeholder in place after signing.
	stage(5, "emit provenance")
	provPath := assembled + provenanceSuffix
	if err := writeProvenance(provPath, opts); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "==> done  %s + provenance.json ready for AVC signing\n", assembled)
	return nil
}

// verifyPayloadInventory asserts that -PayloadDir contains EXACTLY the
// six pinned filenames, no more, no less. Rejects subdirectories and
// symlinks so a mis-staged kit does not slip past.
func verifyPayloadInventory(dir string) error {
	seen := make(map[string]struct{})
	for _, name := range requiredPayloadFiles {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return &ioError{msg: fmt.Sprintf("payload dir missing required file: %s", name)}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return &ioError{msg: fmt.Sprintf("refusing symlink in payload dir: %s", name)}
		}
		if !info.Mode().IsRegular() {
			return &ioError{msg: fmt.Sprintf("refusing non-regular entry in payload dir: %s", name)}
		}
		seen[name] = struct{}{}
	}
	// Reject stray entries so a bundler mistake never lets an extra
	// file slip past unsigned.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return &ioError{msg: fmt.Sprintf("read payload dir: %s", err)}
	}
	for _, e := range entries {
		if _, ok := seen[e.Name()]; !ok {
			return &ioError{msg: fmt.Sprintf("payload dir contains unexpected entry: %s", e.Name())}
		}
	}
	return nil
}
