//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
)

// otlpValidatePerm accepts the canonical 0600 and any tighter mode that keeps
// the owner's read bit (a hardening script's 0400). A group or other bit is
// permission drift: the reader refuses the file, and a reader that already
// holds a verified value keeps it while the root services re-stamp the file.
func otlpValidatePerm(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode == 0o600 || (mode&^0o600 == 0 && mode&0o400 != 0) {
		return nil
	}
	return managedPermissionDrift("OTLP path-token %s has mode %o, want 600", path, mode)
}

// tokenPermissionVerdict marks a token or token folder owner and mode verdict
// as permission drift, so the gateway keeps its cached token and the root
// services repair the file, instead of rejecting every hook request.
// Structural failures never come through here.
func tokenPermissionVerdict(err error) error {
	if err == nil || isManagedPermissionDrift(err) {
		return err
	}
	return managedDriftError{err: err}
}
