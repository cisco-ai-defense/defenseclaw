// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// verifyAuthenticode asserts a Cisco-signed Authenticode signature on
// path. It shells out to signtool.exe verify /pa /q — signtool is the
// canonical Microsoft-authored verifier and the same tool AVC uses to
// SIGN the file. Any other path (Go's own PE parser, x/sys/windows
// WinVerifyTrust) would introduce a second implementation that could
// drift from what AVC's pipeline enforces.
//
// The chain policy /pa asserts a valid Authenticode chain up to a
// trusted root, which is exactly the runtime's expectation. The Cisco-
// specific root pinning is asserted in a subsequent runtime step
// (loadEnterprisePayload rejects manifests whose distribution_flavor
// does not match); this stage only needs to prove "not unsigned."
//
// On non-Windows hosts, signtool is not available. The assembler is
// only ever executed on AVC's Windows runner in production; a caller
// on macOS/Linux (spec 002's local -AllowUnsigned developer loop) skips
// verification entirely via the -AllowUnsigned flag. Reaching this
// function on a non-Windows host without -AllowUnsigned is a
// configuration error worth failing loudly on.
func verifyAuthenticode(path string) error {
	if runtime.GOOS != "windows" {
		return &signatureError{msg: fmt.Sprintf(
			"Authenticode verify requires Windows (running on %s); pass -AllowUnsigned to skip",
			runtime.GOOS,
		)}
	}
	// Use LookPath so a signtool.exe outside PATH surfaces as a
	// signature error (the caller then knows to add the Windows SDK
	// bin dir to PATH) rather than as a mysterious exec failure.
	sigtool, err := exec.LookPath("signtool.exe")
	if err != nil {
		return &signatureError{msg: fmt.Sprintf("signtool.exe not on PATH: %s", err)}
	}
	// /pa  — use Authenticode policy (default chain policy)
	// /q   — quiet: only exit code, no per-file chatter
	cmd := exec.Command(sigtool, "verify", "/pa", "/q", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &signatureError{msg: fmt.Sprintf(
			"signtool verify failed for %s: %s\n%s",
			path, err, strings.TrimSpace(string(out)),
		)}
	}
	return nil
}
