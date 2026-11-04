//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "github.com/defenseclaw/defenseclaw/internal/managed"

// auditDBAncestorOwnerAdvisory reports whether an untrusted owner on path is
// an advisory verdict: path is an ancestor folder of the store inside the
// Secure Client tree or an OS root, whose owner the platform installer or
// the administrator controls. The config walk already treats the same
// folders that way, so both walks reach the same verdict. A standalone
// process (managed.StandaloneTrustScope) keeps the owner verdict fatal.
func auditDBAncestorOwnerAdvisory(path string, directory, strict bool) bool {
	return directory && !strict && !managed.StandaloneTrustScope() && managed.AdvisoryAncestorPath(path)
}
