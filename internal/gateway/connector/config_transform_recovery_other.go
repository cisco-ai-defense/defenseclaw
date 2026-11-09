// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

// RecoverRetainedConfigTransforms has nothing to finish off Windows: the
// compare-and-swap receipts exist only for the Windows transaction protocol,
// and the earlier protocol recovers inside the next change to the same file.
func RecoverRetainedConfigTransforms(string) (int, error) { return 0, nil }
