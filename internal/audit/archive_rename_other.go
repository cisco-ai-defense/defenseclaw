// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux && !darwin

package audit

// renameExclusive has no non-replacing rename to call here, so a file system
// without hard links fails the move closed (renameNoReplace).
func renameExclusive(_, _ string) error {
	return errNoReplaceMoveUnsupported
}
