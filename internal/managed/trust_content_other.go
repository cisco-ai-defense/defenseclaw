// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

// RepairWithContentProof runs repair when path's bytes match the record of
// the last trusted read and reports whether they still match after it. No
// caller off Windows needs it (StandaloneRepairNeedsProvenance is false); it
// keeps the cross-platform gates compiling.
func RepairWithContentProof(path string, repair func()) bool {
	if !TrustedContentUnchanged(path) {
		return false
	}
	repair()
	return TrustedContentUnchanged(path)
}
