// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsServiceLogEnv is the protected SCM environment value the enterprise
// installer pins for each DefenseClaw service it hosts. SCM discards a
// service's stderr, so without it a helper that fails to start, and the
// gateway that depends on it, leave nothing on disk to diagnose.
const windowsServiceLogEnv = "DEFENSECLAW_WINDOWS_SERVICE_LOG"

func serviceLogPath() string {
	return strings.TrimSpace(os.Getenv(windowsServiceLogEnv))
}

// openHelperLog opens the service log for append. The helper runs as
// LocalSystem, so the path is held to the same rules as the credential
// broker's log: clean, absolute, on a local NTFS volume, inside an
// administrator-only directory with no reparse point anywhere on the way,
// and the leaf itself a regular file.
func openHelperLog(path string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("sensor helper log path must be clean and absolute")
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return nil, errors.New("sensor helper log path is not on a trusted local NTFS volume")
	}
	directory := filepath.Dir(path)
	if err := winpath.RejectReparseChain(directory); err != nil {
		return nil, fmt.Errorf("sensor helper log directory: %w", err)
	}
	if err := managed.ValidateTrustedRuntimeDir(directory, "sensor helper log directory"); err != nil {
		return nil, err
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, errors.New("sensor helper log path is invalid")
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_APPEND_DATA|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open sensor helper log: %w", err)
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil ||
		information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("sensor helper log has an unsafe file type")
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("sensor helper log is unavailable")
	}
	return file, nil
}
