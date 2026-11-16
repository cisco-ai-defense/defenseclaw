//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// otlpValidatePerm accepts the canonical 0600 and any tighter mode that keeps
// the owner's read bit (a hardening script's 0400). A group or other bit is
// permission drift: the reader refuses the file, and a reader that already
// holds a verified value keeps it while the root services re-stamp the file.
// Outside the Secure Client drift scope (tokenDriftStrict) it is a plain
// refusal, as before.
func otlpValidatePerm(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode == 0o600 || (mode&^0o600 == 0 && mode&0o400 != 0) {
		return nil
	}
	if tokenDriftStrict() {
		return fmt.Errorf("OTLP path-token %s has mode %o, want 600", path, mode)
	}
	return managedPermissionDrift("OTLP path-token %s has mode %o, want 600", path, mode)
}

// tokenPermissionVerdict marks a token or token folder owner and mode verdict
// as permission drift, so the gateway keeps its cached token and the root
// services repair the file, instead of rejecting every hook request.
// Structural failures never come through here. Per-user, standalone and
// TrustStrictAncestorsEnv keep the verdict unclassified (tokenDriftStrict).
func tokenPermissionVerdict(err error) error {
	if err == nil || isManagedPermissionDrift(err) || tokenDriftStrict() {
		return err
	}
	return managedDriftError{err: err}
}

// tokenDriftStrict reports that token verdicts stay plain refusals: strict
// mode is pinned, or this is not a managed Secure Client process.
func tokenDriftStrict() bool {
	return managed.TrustStrictAncestors() || !secureClientManagedRuntime()
}

// otlpValidateCredentialPerm is otlpValidatePerm: the Windows broad-reader
// rule for credentials has no counterpart in the mode bits checked here.
func otlpValidateCredentialPerm(path string, info os.FileInfo) error {
	return otlpValidatePerm(path, info)
}
