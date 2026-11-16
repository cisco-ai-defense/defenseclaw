// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package audit

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// renameExclusive is renamex_np with RENAME_EXCL: it fails with EEXIST when
// to exists. ENOTSUP and EINVAL mean the file system lacks the flag.
func renameExclusive(from, to string) error {
	err := unix.RenamexNp(from, to, unix.RENAME_EXCL)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("%w: renamex_np: %w", errNoReplaceMoveUnsupported, err)
	}
	return err
}
