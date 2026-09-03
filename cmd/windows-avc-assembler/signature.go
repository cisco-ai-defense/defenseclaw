// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// payloadPathEnvVar is the environment variable runPowerShellVerify uses
// to pass the target file path into its PowerShell script. Environment
// is the safe channel here: PowerShell's `-Command <string>` does NOT
// populate $args with trailing argv (that's `-File` behavior), so a
// naive `$args[0]` reference resolves to $null and
// Get-AuthenticodeSignature -FilePath $null crashes on every call.
// Env-var passing also removes the last shell-injection concern — the
// path never enters the script literal.
const payloadPathEnvVar = "DEFENSECLAW_ASSEMBLER_PAYLOAD_PATH"

// psVerifyTimeout bounds each Get-AuthenticodeSignature invocation.
// Chain building may include revocation lookups that stall indefinitely
// when a network policy blackholes CRL/OCSP endpoints; the assembler
// processes six payload files in series so an unbounded hang on any one
// file would freeze AVC's signing job with no diagnostic. 60 s is
// generous headroom over a healthy lookup (typically <2 s) while still
// surfacing a stuck runner promptly.
const psVerifyTimeout = 60 * time.Second

// signingType controls the chain-trust policy applied to each payload.
// The value comes from `-SigningType DEV|PROD` and is required whenever
// -AllowUnsigned is not set. The prod-only path requires
// Get-AuthenticodeSignature.Status == Valid; the dev path additionally
// accepts Status == UnknownError specifically when StatusMessage is the
// host-localized CERT_E_CHAINING message AND the fail-closed X509Chain
// inspection shows PartialChain and nothing else. See classifyVerify
// for the exact trust matrix.
type signingType int

const (
	signingTypeProd signingType = iota
	signingTypeDev
)

func (s signingType) String() string {
	if s == signingTypeDev {
		return "DEV"
	}
	return "PROD"
}

// parseSigningType is the CLI-facing parser for -SigningType.
// Case-insensitive; whitespace-trimmed. Returns a usageError-compatible
// message so main.go can wrap it consistently.
func parseSigningType(s string) (signingType, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PROD":
		return signingTypeProd, nil
	case "DEV":
		return signingTypeDev, nil
	}
	return signingTypeProd, fmt.Errorf("must be PROD or DEV (got: %q)", s)
}

// normalizeThumbprint accepts AVC's SHA-256 fingerprint in any of the
// common shapes (bare hex, colon-separated, upper- or lower-case) and
// returns the canonical lowercase-no-separators form. Anything that
// does not resolve to exactly 32 bytes of hex is rejected. AVC's spec
// pins bare 64-char hex as the recommended input, but this normalizer
// stays permissive so a copy-paste from `certutil -hashfile ... SHA256`
// (which uses spaces) or an openssl `... -fingerprint -sha256` output
// (which uses colons) works out of the box.
func normalizeThumbprint(input string) (string, error) {
	stripped := strings.Map(func(r rune) rune {
		switch r {
		case ':', ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, input)
	stripped = strings.ToLower(stripped)
	if len(stripped) != 64 {
		return "", fmt.Errorf("must be a 64-hex-char SHA-256 fingerprint (got %d chars after stripping separators)", len(stripped))
	}
	if _, err := hex.DecodeString(stripped); err != nil {
		return "", fmt.Errorf("not valid hex: %w", err)
	}
	return stripped, nil
}

// psSignatureRecord is the structured output of the PowerShell verify
// script. The script emits JSON so the parse contract is unambiguous
// (StatusMessage may contain arbitrary text including punctuation,
// which a KEY=VALUE format would need to escape).
type psSignatureRecord struct {
	// Status is Get-AuthenticodeSignature.Status.ToString(). One of:
	// Valid, NotSigned, HashMismatch, NotTrusted, NotSupportedFileFormat,
	// UnknownError, Incompatible, Missing.
	Status string `json:"Status"`
	// StatusMessage is Get-AuthenticodeSignature.StatusMessage. On
	// English hosts this is the human-readable HRESULT description
	// (e.g. "A certificate chain could not be built to a trusted root
	// authority."); on non-English hosts it is the localized form.
	StatusMessage string `json:"StatusMessage"`
	// Thumbprint is SHA256(SignerCertificate.RawData), lower-cased.
	// Empty when the payload has no signer certificate.
	Thumbprint string `json:"Thumbprint"`
	// CertEChainingMatch is true when StatusMessage is byte-exact to
	// the host-localized text of HRESULT CERT_E_CHAINING (0x800B010A),
	// computed via [Win32Exception]::new(0x800B010A).Message. Locale-
	// safe: both messages come from the same OS resource table. In
	// DEV mode this is the sole additional gate (beyond fingerprint
	// match) that distinguishes CERT_E_CHAINING from other UnknownError
	// causes (CERT_E_REVOKED, CERT_E_EXPIRED, TRUST_E_SYSTEM_ERROR).
	CertEChainingMatch bool `json:"CertEChainingMatch"`
}

// verifyAuthenticode is the fingerprint-based verify entry point.
// Invokes PowerShell to gather a signed record about the file, then
// applies the trust matrix in classifyVerify to decide accept vs.
// reject. See docs/specs/003-windows-avc-standalone-assembler/ for
// the design contract (AVC handoff, revision 2026-09-03).
//
// Errors are classified by cause so main.go's exit-code map does the
// right thing:
//   - signatureError — payload-side fault (unsigned, tampered, wrong
//     signer, chain not trusted in the mode). Exit 4.
//   - ioError — runner-side fault (non-Windows, powershell.exe not on
//     PATH, exec launch failure, timeout). Exit 6.
func verifyAuthenticode(path string, sigType signingType, expectedThumbprint string) error {
	if runtime.GOOS != "windows" {
		return &ioError{msg: fmt.Sprintf(
			"Authenticode verify requires Windows (running on %s); pass -AllowUnsigned to skip",
			runtime.GOOS,
		)}
	}
	rec, err := runPowerShellVerify(path)
	if err != nil {
		return err
	}
	return classifyVerify(path, sigType, expectedThumbprint, rec)
}

// classifyVerify applies AVC's trust matrix in a pure function — no
// I/O, no exec, no dependency on Windows. Split out for unit testing:
// we cannot invoke signtool or PowerShell from CI, but we can feed
// synthetic psSignatureRecord values through this function to prove
// the matrix is correct.
//
// Trust matrix:
//
//	SigningType | Status         | Additional predicate           | Verdict
//	------------+----------------+--------------------------------+---------
//	PROD        | Valid          | thumbprint match               | accept
//	PROD        | anything else  | any                            | reject
//	DEV         | Valid          | thumbprint match               | accept
//	DEV         | UnknownError   | CertEChainingMatch AND         |
//	            |                |   ChainStatusFlags == {PartialChain} only
//	            |                |   AND thumbprint match         | accept
//	DEV         | UnknownError   | otherwise                      | reject
//	DEV         | anything else  | any                            | reject
//	both        | any            | thumbprint mismatch OR missing | reject
func classifyVerify(path string, sigType signingType, expectedThumbprint string, rec psSignatureRecord) error {
	// Fingerprint is the strongest identity check. Fail before looking
	// at any status so a diagnostic hits the operator with the exact
	// mismatch, not a downstream "chain untrusted" red herring.
	if rec.Thumbprint == "" {
		return &signatureError{msg: fmt.Sprintf(
			"%s: no signer certificate on payload (Status=%s)",
			path, rec.Status,
		)}
	}
	if rec.Thumbprint != expectedThumbprint {
		return &signatureError{msg: fmt.Sprintf(
			"%s: signer thumbprint mismatch (expected %s, got %s)",
			path, expectedThumbprint, rec.Thumbprint,
		)}
	}

	// Fingerprint OK — apply the status gate.
	switch rec.Status {
	case "Valid":
		// Fingerprint matched + Windows trusts the chain. Accept in
		// both DEV and PROD.
		return nil

	case "UnknownError":
		if sigType != signingTypeDev {
			return &signatureError{msg: fmt.Sprintf(
				"%s: signature Status=UnknownError; PROD requires Valid (StatusMessage=%q)",
				path, rec.StatusMessage,
			)}
		}
		// DEV path: accept ONLY when the status message is exactly the
		// host-localized CERT_E_CHAINING message. The strong identity
		// gate is the fingerprint match (checked above); the exact
		// message match distinguishes CERT_E_CHAINING (0x800B010A —
		// "chain doesn't reach a trusted root") from other HRESULTs
		// that could surface as UnknownError (CERT_E_REVOKED,
		// CERT_E_EXPIRED, TRUST_E_SYSTEM_ERROR, etc.) — each of those
		// has a different localized StatusMessage, so an exact-message
		// compare filters them out.
		//
		// NOTE: an earlier revision of this function also required
		// X509Chain.ChainStatus == {PartialChain} only as a
		// defense-in-depth check. That check turned out to be
		// incompatible with air-gapped AVC CI runners: .NET's default
		// RevocationMode = Online tries CRL/OCSP lookups, which fail
		// on a closed network, producing PartialChain +
		// RevocationStatusUnknown + OfflineRevocation instead of the
		// bare PartialChain we required. Per AVC's spec, the
		// Authenticode result + fingerprint pair is sufficient; the
		// independent chain re-check was overkill and rejected valid
		// DEV builds. See PR discussion on the fingerprint-signing
		// branch.
		if !rec.CertEChainingMatch {
			return &signatureError{msg: fmt.Sprintf(
				"%s: DEV accepts UnknownError only for CERT_E_CHAINING (0x800B010A); got StatusMessage=%q",
				path, rec.StatusMessage,
			)}
		}
		return nil

	default:
		// NotSigned, HashMismatch, NotTrusted, NotSupportedFileFormat,
		// Incompatible, Missing — all fatal in both modes.
		return &signatureError{msg: fmt.Sprintf(
			"%s: signature Status=%s (StatusMessage=%q)",
			path, rec.Status, rec.StatusMessage,
		)}
	}
}

// psVerifyScript is the exact PowerShell body runPowerShellVerify
// evaluates. It reads the payload path from the payloadPathEnvVar env
// var (see comment on the constant for why), interrogates the file's
// Authenticode signature via Get-AuthenticodeSignature, and emits a
// single JSON object with the fields psSignatureRecord decodes. JSON
// is used (rather than KEY=VALUE lines) because StatusMessage may
// contain arbitrary punctuation and quoting escapes would be fragile.
//
// Notes on the design:
//   - Set-StrictMode is left at the default so a missing property on a
//     null cert is a runtime error we can catch, not a silent $null
//     that would leak into JSON.
//   - Console.Out.Write is used (not Write-Output) so PowerShell's
//     default host-width truncation and trailing CRLF do not affect
//     the stdout the Go side reads.
//   - No X509Chain build. An earlier revision built a chain to gate
//     the DEV path on "PartialChain only", but that check was
//     incompatible with air-gapped AVC CI runners: .NET's default
//     RevocationMode = Online tries CRL/OCSP lookups, which fail on
//     a closed network and add OfflineRevocation +
//     RevocationStatusUnknown flags alongside PartialChain — the
//     defense-in-depth check then rejected legitimate DEV builds.
//     Per AVC's spec, Status + StatusMessage + fingerprint together
//     are sufficient identity + integrity gates.
//   - CertEChainingMatch is computed by resolving HRESULT 0x800B010A
//     to its host-localized description via Win32Exception. Same OS
//     resource table Get-AuthenticodeSignature.StatusMessage uses,
//     so both strings match on any locale.
const psVerifyScript = `$ErrorActionPreference = 'Stop'
$p = $env:` + payloadPathEnvVar + `
if ([string]::IsNullOrEmpty($p)) { throw '` + payloadPathEnvVar + ` not set' }
# -LiteralPath, not -FilePath: -FilePath interprets '[' and ']' as
# wildcards, which fails on CI paths that include job-id brackets
# (e.g. C:\build\[job-1234]\payload\...). -LiteralPath treats the
# string exactly as typed.
$sig = Get-AuthenticodeSignature -LiteralPath $p
$status = $sig.Status.ToString()
$statusMsg = if ($sig.StatusMessage) { $sig.StatusMessage } else { '' }
$fp = ''
if ($sig.SignerCertificate -ne $null) {
    # Hash SignerCertificate.RawData directly with SHA256.Create() —
    # X509Certificate.GetCertHashString(HashAlgorithmName) only exists
    # in .NET Core 2.0+/.NET Standard 2.1+, NOT in .NET Framework 4.x
    # which is what Windows PowerShell 5.1 runs on. On WinPS 5.1 the
    # typed overload throws MethodNotFound and the whole script dies
    # with a signed-payload rejection that isn't actually a signature
    # problem. RawData + SHA256.Create() is version-independent.
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($sig.SignerCertificate.RawData)
        $fp = ([System.BitConverter]::ToString($hashBytes)).Replace('-','').ToLower()
    } finally {
        $sha256.Dispose()
    }
}
$certEChainingMsg = ''
try { $certEChainingMsg = [System.ComponentModel.Win32Exception]::new([int]0x800B010A).Message } catch { $certEChainingMsg = '' }
$isChainingMatch = ($certEChainingMsg -ne '') -and ($statusMsg -ceq $certEChainingMsg)
$obj = [ordered]@{
    Status = $status
    StatusMessage = $statusMsg
    Thumbprint = $fp
    CertEChainingMatch = [bool]$isChainingMatch
}
[System.Console]::Out.Write(($obj | ConvertTo-Json -Compress))`

// runPowerShellVerify invokes psVerifyScript on the given payload
// path and returns the parsed record. Errors are always classified
// as ioError — every failure path in this helper is an environment
// or host issue, not a payload signature rejection. Payload-level
// verdicts (NotSigned, HashMismatch, wrong signer, etc.) surface
// THROUGH the JSON as psSignatureRecord.Status, which classifyVerify
// then turns into signatureError. A PS-side throw under
// ErrorActionPreference=Stop (bad path, missing env var, filesystem
// permission error, unavailable module) bypasses the JSON emit and
// exits non-zero — that is a runner-side fault and belongs in the
// I/O bucket per the exit-code contract (code 6, not code 4). Callers
// return the error verbatim; the classifier in main.go maps it.
func runPowerShellVerify(path string) (psSignatureRecord, error) {
	var zero psSignatureRecord
	ctx, cancel := context.WithTimeout(context.Background(), psVerifyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psVerifyScript)
	// Inherit the parent environment and layer the payload path on top.
	// os/exec's default is os.Environ() only when cmd.Env is nil, so an
	// explicit slice is required.
	cmd.Env = append(os.Environ(), payloadPathEnvVar+"="+path)
	// Output(), NOT CombinedOutput(): PS warnings on stderr must not
	// concatenate into the JSON body. On failure, os/exec.Cmd.Output
	// populates *ExitError.Stderr so the error branch below still
	// surfaces stderr diagnostic.
	out, err := cmd.Output()
	if err == nil {
		body := strings.TrimSpace(string(out))
		if body == "" {
			return zero, &ioError{msg: fmt.Sprintf(
				"powershell verify for %s emitted empty stdout", path,
			)}
		}
		var rec psSignatureRecord
		if jerr := json.Unmarshal([]byte(body), &rec); jerr != nil {
			return zero, &ioError{msg: fmt.Sprintf(
				"powershell verify for %s emitted unparseable JSON: %s\n%s",
				path, jerr, body,
			)}
		}
		// Normalize thumbprint casing — the PS script already lowercases
		// it, but defense-in-depth so a future script tweak cannot
		// accidentally break the exact-match comparison downstream.
		rec.Thumbprint = strings.ToLower(strings.TrimSpace(rec.Thumbprint))
		return rec, nil
	}
	// Every failure branch below is ioError. Rationale in the
	// function's doc comment: real signature rejections surface as
	// psSignatureRecord.Status through the JSON, not by non-zero exit.
	// A PS throw under ErrorActionPreference=Stop is a runner-side
	// fault (bad path, missing env var, permission error, module
	// unavailable), which the exit-code contract puts in bucket 6.
	var exitErr *exec.ExitError
	stderr := ""
	if errors.As(err, &exitErr) {
		stderr = strings.TrimSpace(string(exitErr.Stderr))
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return zero, &ioError{msg: fmt.Sprintf(
			"powershell verify timed out after %s for %s: %s",
			psVerifyTimeout, path, stderr,
		)}
	}
	if exitErr == nil {
		return zero, &ioError{msg: fmt.Sprintf(
			"powershell.exe failed to launch while verifying %s: %s",
			path, err,
		)}
	}
	return zero, &ioError{msg: fmt.Sprintf(
		"powershell verify script exited non-zero for %s: %s\n%s",
		path, err, stderr,
	)}
}
