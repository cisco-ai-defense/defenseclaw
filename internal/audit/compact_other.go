// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package audit

import "errors"

// validateServiceOwnedAuditDB: on Linux and macOS a managed store is
// compacted as the gateway service account that owns it, through the store's
// own custody checks, so there is no administrator open.
func validateServiceOwnedAuditDB(string, bool) error {
	return errors.New("audit: a service-owned compaction runs only on managed Windows; " +
		"on Linux and macOS it runs as the gateway service account")
}
