// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// payloadPathEnvVar is the environment variable readSignerSubjectCN
// uses to pass the target file path into its PowerShell script.
// Environment is the safe channel here: PowerShell's `-Command <string>`
// does NOT populate $args with trailing argv (that's `-File` behavior),
// so a naive `$args[0]` reference resolves to $null and
// Get-AuthenticodeSignature -FilePath $null crashes on every call.
// Env-var passing also removes the last shell-injection concern — the
// path never enters the script literal.
const payloadPathEnvVar = "DEFENSECLAW_ASSEMBLER_PAYLOAD_PATH"

// ciscoPublisherCN pins the Subject Common Name the payload's
// Authenticode signature MUST resolve to. Matches the exact string the
// shell assembler's assert-cisco-signature.{sh,ps1} pinned. `signtool
// verify /n <cn>` accepts a SUBSTRING match per Microsoft's
// documentation, so /n alone would let a certificate whose subject
// merely CONTAINS this string (e.g. an internal "Cisco Systems, Inc.
// Test Root") pass verification. verifyAuthenticode below therefore
// runs a follow-up exact-equality check on the actual signer
// certificate's Subject CN after signtool passes.
const ciscoPublisherCN = "Cisco Systems, Inc."

// signtoolVerifyTimeout bounds each signtool verify call. Authenticode
// chain building includes revocation lookups (CRL/OCSP) that stall
// indefinitely when a network policy blackholes those endpoints; the
// assembler processes six payload files in series so an unbounded
// hang on any one file would freeze AVC's signing job with no
// diagnostic. 60 seconds is generous headroom over a healthy lookup
// (typically <2 s) while still surfacing a stuck runner promptly.
const signtoolVerifyTimeout = 60 * time.Second

// verifyAuthenticode asserts a Cisco-signed Authenticode signature on
// path. It is a two-stage gate:
//
//  1. Chain trust: `signtool verify /pa /n <cn> /q` — Microsoft's
//     canonical verifier confirms a valid Authenticode chain up to a
//     trusted root, narrowing accepted signers to those whose Subject
//     matches the ciscoPublisherCN substring.
//  2. Exact identity: read the actual signer certificate's Subject CN
//     via readSignerSubjectCN and assert exact equality with
//     ciscoPublisherCN. This closes the gap that /n's substring match
//     leaves — a "Cisco Systems, Inc. (Test Root)" cert would pass
//     step 1 but fails step 2.
//
// Errors are classified by cause:
//   - signatureError — signtool exited non-zero (payload unsigned,
//     signed by non-Cisco publisher, or broken chain) OR the exact CN
//     check found a mismatch. Maps to exit-code 4.
//   - ioError — environmental faults (non-Windows host, signtool /
//     powershell not on PATH, exec.Cmd failed to launch, timeout).
//     Runner-side problems, not payload-side signature rejection;
//     maps to exit-code 6. Keeping the buckets distinct lets AVC's CI
//     separate a legitimately unsigned payload from a runner missing
//     the Windows SDK or PowerShell.
func verifyAuthenticode(path string) error {
	if runtime.GOOS != "windows" {
		return &ioError{msg: fmt.Sprintf(
			"Authenticode verify requires Windows (running on %s); pass -AllowUnsigned to skip",
			runtime.GOOS,
		)}
	}
	if err := runSigntoolVerify(path); err != nil {
		return err
	}
	cn, err := readSignerSubjectCN(path)
	if err != nil {
		return err
	}
	return assertCNIsCisco(path, cn)
}

// runSigntoolVerify is the chain-trust gate. Returns nil on success,
// signatureError on a real verify rejection (started process, non-zero
// exit), or ioError on environmental faults (missing signtool,
// timeout, exec launch failure).
func runSigntoolVerify(path string) error {
	sigtool, err := exec.LookPath("signtool.exe")
	if err != nil {
		return &ioError{msg: fmt.Sprintf("signtool.exe not on PATH: %s", err)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), signtoolVerifyTimeout)
	defer cancel()
	// /pa               — Authenticode policy (default chain policy)
	// /n <cn>           — narrow accepted signers by Subject substring
	//                     (exact match is enforced by readSignerSubjectCN below)
	// /q                — quiet: only exit code, no per-file chatter
	cmd := exec.CommandContext(ctx, sigtool, "verify", "/pa", "/n", ciscoPublisherCN, "/q", path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	// Distinguish causes in order of confidence:
	//   1) context deadline exceeded → timeout (env fault)
	//   2) *exec.ExitError → process started + exited non-zero → real verify rejection
	//   3) anything else → process failed to start → env fault
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &ioError{msg: fmt.Sprintf(
			"signtool verify timed out after %s for %s (network policy may be blocking CRL/OCSP): %s",
			signtoolVerifyTimeout, path, strings.TrimSpace(string(out)),
		)}
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		// os/exec returns *ExitError only when the process actually
		// ran to completion. A different error type (fs.PathError from
		// LookPath was already handled; here it would be things like
		// EPERM from a Job Object policy, or an EFAULT from an AV
		// blocking exec) means signtool never started. That is a
		// runner-side environmental fault, not a signature rejection.
		return &ioError{msg: fmt.Sprintf(
			"signtool verify failed to launch for %s: %s\n%s",
			path, err, strings.TrimSpace(string(out)),
		)}
	}
	return &signatureError{msg: fmt.Sprintf(
		"signtool verify failed for %s: %s\n%s",
		path, err, strings.TrimSpace(string(out)),
	)}
}

// readSignerSubjectCN returns the Subject Common Name of the file's
// Authenticode signer certificate. Uses PowerShell's
// Get-AuthenticodeSignature (already required on AVC's Windows runner
// for the payload's install-enterprise.ps1 signing step, so no new
// dependency) and .NET's X509Certificate2.GetNameInfo(SimpleName) — the
// same method the retired assert-cisco-signature.ps1 used. On error,
// distinguishes exec-launch failures (ioError) from a PS-reported
// invalid signature status (signatureError).
func readSignerSubjectCN(path string) (string, error) {
	// Path passed via env var, not $args[0]: PowerShell's
	// `-Command <string>` does not populate $args (that behavior is
	// exclusive to `-File`), so a naive $args[0] read resolves to
	// $null and Get-AuthenticodeSignature -FilePath $null crashes on
	// every invocation. Env-var passing also keeps the path out of
	// the script literal, eliminating any shell-injection surface for
	// pathological file names.
	//
	// ErrorActionPreference=Stop makes any underlying failure surface
	// as a non-zero exit. Writing the CN via [Console]::Out.Write
	// (rather than the default pipeline) avoids Powershell's
	// terminal-width truncation and the trailing CRLF Write-Host adds.
	script := `$ErrorActionPreference='Stop';` +
		`$p = $env:` + payloadPathEnvVar + `;` +
		`if ([string]::IsNullOrEmpty($p)) { throw "` + payloadPathEnvVar + ` not set" };` +
		`$sig = Get-AuthenticodeSignature -FilePath $p;` +
		`if ($sig.Status -ne 'Valid') { throw "signature status is $($sig.Status)" };` +
		`[System.Console]::Out.Write(` +
		`  $sig.SignerCertificate.GetNameInfo(` +
		`    [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,` +
		`    $false))`
	ctx, cancel := context.WithTimeout(context.Background(), signtoolVerifyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	// Inherit the parent environment and layer the payload path on top —
	// os/exec's default is os.Environ() only when cmd.Env is nil, so an
	// explicit slice is required.
	cmd.Env = append(os.Environ(), payloadPathEnvVar+"="+path)
	// Use Output(), NOT CombinedOutput(): a PowerShell warning on
	// stderr (e.g. verbose module load, deprecated cmdlet notices)
	// would otherwise be concatenated into stdout and would
	// contaminate the CN string, causing exact-equality with
	// ciscoPublisherCN to fail on a correctly signed payload. On
	// failure, os/exec.Cmd.Output populates *ExitError.Stderr so the
	// error branch below still gets the diagnostic.
	out, err := cmd.Output()
	if err == nil {
		// Strip ONLY the transport terminator (a trailing CRLF that
		// PowerShell's stdio may append when running under a console
		// host); do NOT use strings.TrimSpace here — .NET's
		// X509Certificate2.GetNameInfo(SimpleName) preserves whitespace
		// verbatim, so a cert with a padded CN like " Cisco Systems, Inc. "
		// would otherwise be silently normalized to the pinned string
		// and pass the exact-equality check downstream, defeating the
		// gap-closing purpose of that check (signtool's /n substring
		// match already accepts padded look-alikes).
		cn := strings.TrimRight(string(out), "\r\n")
		if cn == "" {
			return "", &signatureError{msg: fmt.Sprintf(
				"%s: empty signer Subject CN — cert has no SimpleName",
				path,
			)}
		}
		return cn, nil
	}
	// Recover stderr from *ExitError for a useful diagnostic — on
	// non-*ExitError failures (exec launch problems) stderr is
	// unavailable so we fall back to err.Error() alone.
	var exitErr *exec.ExitError
	stderr := ""
	if errors.As(err, &exitErr) {
		stderr = strings.TrimSpace(string(exitErr.Stderr))
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", &ioError{msg: fmt.Sprintf(
			"read signer CN timed out after %s for %s: %s",
			signtoolVerifyTimeout, path, stderr,
		)}
	}
	if exitErr == nil {
		return "", &ioError{msg: fmt.Sprintf(
			"powershell.exe failed to launch while reading signer CN for %s: %s",
			path, err,
		)}
	}
	// PowerShell exited non-zero — Get-AuthenticodeSignature reported
	// a non-Valid status, or the throw fired. Treat as a signature
	// rejection.
	return "", &signatureError{msg: fmt.Sprintf(
		"read signer CN failed for %s: %s\n%s",
		path, err, stderr,
	)}
}

// assertCNIsCisco enforces exact equality of the observed Subject
// Common Name with ciscoPublisherCN. Split out for direct unit testing
// — we cannot mock signtool or PowerShell from a Go test, but we can
// exercise the string-comparison logic against representative "look-
// alike" subjects that would slip past signtool's /n substring match.
func assertCNIsCisco(path, observedCN string) error {
	if observedCN == ciscoPublisherCN {
		return nil
	}
	return &signatureError{msg: fmt.Sprintf(
		"%s: signer Subject CN mismatch (expected %q, got %q)",
		path, ciscoPublisherCN, observedCN,
	)}
}
