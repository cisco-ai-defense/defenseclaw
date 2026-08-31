// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func validateHookRuntimeOpenedFile(file *os.File, label string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&info,
	); err != nil {
		return fmt.Errorf("inspect opened %s: %w", label, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		info.NumberOfLinks != 1 {
		return fmt.Errorf(
			"%s must be a no-reparse single-link regular file (links=%d)",
			label,
			info.NumberOfLinks,
		)
	}
	return nil
}
