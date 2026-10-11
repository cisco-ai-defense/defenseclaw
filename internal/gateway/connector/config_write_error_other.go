// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"os"
	"syscall"
)

func configWritePermissionDenied(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EROFS)
}
