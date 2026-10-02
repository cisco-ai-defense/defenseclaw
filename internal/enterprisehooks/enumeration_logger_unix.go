//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// logfSafely is the nil-safe EnumerationLogger call used by the Unix
// enumerator (the Windows enumerator carries its own copy).
func logfSafely(logf EnumerationLogger, subject, reason string) {
	if logf == nil {
		return
	}
	logf(subject, reason)
}
