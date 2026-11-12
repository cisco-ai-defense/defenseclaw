// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"fmt"
	"os"
	"syscall"
)

// unprotectedAgentsRecordTrusted is the protection the enumerator gives the
// record (writeUnixRootOnlyRecord): a single-link 0600 file owned by the
// account that runs the enumerator, which is root in production. A record
// with more access than that is not one the enumerator wrote.
func unprotectedAgentsRecordTrusted(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("enterprise hooks: unprotected agents record %s must be a 0600 file", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) {
		return fmt.Errorf("enterprise hooks: unprotected agents record %s is not a single-link file of the enumerator account", path)
	}
	return nil
}
