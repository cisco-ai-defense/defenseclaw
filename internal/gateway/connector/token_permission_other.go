//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
)

// otlpValidatePerm enforces that the token file is not group/other accessible.
// On Unix the file is created 0600, so anything else is a tampering signal.
func otlpValidatePerm(path string, info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode != 0o600 {
		return fmt.Errorf("OTLP path-token %s has mode %o, want 600", path, mode)
	}
	return nil
}

// tokenPermissionVerdict leaves token verdicts as they are on this platform.
func tokenPermissionVerdict(err error) error { return err }

// otlpValidateCredentialPerm is otlpValidatePerm: the Windows broad-reader
// rule for credentials has no counterpart in the mode bits checked here.
func otlpValidateCredentialPerm(path string, info os.FileInfo) error {
	return otlpValidatePerm(path, info)
}
