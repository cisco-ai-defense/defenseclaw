// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package audit

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// renameExclusive is renameat2 with RENAME_NOREPLACE: it fails with EEXIST
// when to exists. EINVAL, ENOSYS and EOPNOTSUPP mean the kernel or the file
// system lacks the flag.
func renameExclusive(from, to string) error {
	err := unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("%w: renameat2: %w", errNoReplaceMoveUnsupported, err)
	}
	return err
}
