//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"fmt"
	"os"
	"syscall"
)

func validateReadOwnerAndLinks(info os.FileInfo, _ *os.File) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect owner and link count")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("hard links are not allowed")
	}
	euid := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != euid {
		return fmt.Errorf("owner uid %d is neither root nor current uid %d", stat.Uid, euid)
	}
	return nil
}

func openRegularNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
