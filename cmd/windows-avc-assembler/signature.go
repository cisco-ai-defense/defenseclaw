// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ciscoPublisherCN pins the Subject Common Name the payload's
// Authenticode signature MUST resolve to. Matches the exact string the
// shell assembler's assert-cisco-signature.{sh,ps1} pinned. `signtool
// verify /n <cn>` accepts a substring match, so passing the fully
// qualified CN prevents a match against any similarly-prefixed
// publisher (e.g. an internal Cisco test cert).
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
// path. It shells out to signtool.exe verify /pa /n "Cisco Systems, Inc." /q —
// signtool is the canonical Microsoft-authored verifier and the same
// tool AVC uses to SIGN the file. Any other path (Go's own PE parser,
// x/sys/windows WinVerifyTrust) would introduce a second
// implementation that could drift from what AVC's pipeline enforces.
//
// The chain policy /pa asserts a valid Authenticode chain up to a
// trusted root. `/n <ciscoPublisherCN>` narrows the accepted signers
// to Cisco specifically — without it, /pa accepts any publisher whose
// chain terminates in the machine's trusted roots (e.g. Microsoft or
// third-party ISVs), which would let a mis-signed payload slip past.
//
// Errors are classified by cause:
//   - signatureError — signtool exited non-zero, signaling the payload
//     is either unsigned, signed by a non-Cisco publisher, or has a
//     broken chain. Maps to the caller's exit-code 4 contract.
//   - ioError — environmental faults (non-Windows host, signtool not
//     on PATH, execution timeout). These are runner-side problems, not
//     a payload-side signature rejection; the exit-code contract
//     defines 6 as the correct "missing input / environment" bucket.
//     Keeping the two buckets distinct lets AVC's CI separate a
//     legitimately unsigned payload from a runner missing the
//     Windows SDK.
func verifyAuthenticode(path string) error {
	if runtime.GOOS != "windows" {
		return &ioError{msg: fmt.Sprintf(
			"Authenticode verify requires Windows (running on %s); pass -AllowUnsigned to skip",
			runtime.GOOS,
		)}
	}
	// Use LookPath so a signtool.exe outside PATH surfaces as an I/O
	// error (the caller then knows to add the Windows SDK bin dir to
	// PATH) rather than as a mysterious exec failure or a misleading
	// "signature rejected" diagnostic.
	sigtool, err := exec.LookPath("signtool.exe")
	if err != nil {
		return &ioError{msg: fmt.Sprintf("signtool.exe not on PATH: %s", err)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), signtoolVerifyTimeout)
	defer cancel()
	// /pa               — use Authenticode policy (default chain policy)
	// /n <ciscoPublisherCN> — require this exact Subject CN
	// /q                — quiet: only exit code, no per-file chatter
	cmd := exec.CommandContext(ctx, sigtool, "verify", "/pa", "/n", ciscoPublisherCN, "/q", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Distinguish a timeout (runner-side environmental fault:
		// slow / blackholed CRL or OCSP) from a real verify rejection
		// (payload-side fault). Both surface as a non-zero exit from
		// signtool, but the context error is the reliable signal for
		// the former.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &ioError{msg: fmt.Sprintf(
				"signtool verify timed out after %s for %s (network policy may be blocking CRL/OCSP): %s",
				signtoolVerifyTimeout, path, strings.TrimSpace(string(out)),
			)}
		}
		return &signatureError{msg: fmt.Sprintf(
			"signtool verify failed for %s: %s\n%s",
			path, err, strings.TrimSpace(string(out)),
		)}
	}
	return nil
}
