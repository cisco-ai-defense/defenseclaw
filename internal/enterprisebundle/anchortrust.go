// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// AnchorsPath is <etc>/trust/bundle-anchors.json of the standalone layout
// of goos.
func AnchorsPath(goos string) (string, error) {
	layout, err := Layout(goos)
	if err != nil {
		return "", err
	}
	return filepath.Join(layout.ConfigDir, "trust", AnchorsName), nil
}

// TrustAnchorFile is the trust check of the anchor file on a device: the
// managed policy-file check (on Linux and macOS owned by root, not group
// or other writable and no ACL write entry, on Windows owned by SYSTEM or
// Administrators with no write entry for other accounts; no links), for the
// file and every folder above it. It keeps that exact owner and writer
// rule on every profile, without the Secure Client drift acceptances of the
// ordinary walk.
func TrustAnchorFile(path string) error {
	return managed.ValidateTrustedFilePathStandalone(path, "bundle trust anchors")
}
