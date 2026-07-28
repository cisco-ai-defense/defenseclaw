// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"os"
	"path/filepath"
)

func prepareSecureParent(path string) error {
	parent := filepath.Dir(path)
	// The immediate parent is the adapter's filesystem trust anchor. Platform
	// system aliases in earlier ancestors (for example macOS /var -> /private/var)
	// are allowed, but the resolved immediate parent itself must be a real,
	// trusted, non-group/other-writable directory. Every open/reopen revalidates
	// this anchor, and leaf opens independently refuse links/reparse points and
	// aliases. Writes use the already-validated file descriptor, so a later
	// ancestor rename cannot redirect bytes into a replacement pathname.
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return ioFailure()
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return ioFailure()
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return unsafeFailure()
	}
	return validateSecureDirectory(parent, info)
}

func securePathMatches(path string, file *os.File, identity os.FileInfo) (bool, error) {
	if file == nil || identity == nil {
		return false, ioFailure()
	}
	opened, err := file.Stat()
	if err != nil {
		return false, ioFailure()
	}
	if !os.SameFile(opened, identity) {
		return false, unsafeFailure()
	}
	if err := validateSecureOpenFile(file); err != nil {
		return false, err
	}
	pathInfo, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, ioFailure()
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return false, unsafeFailure()
	}
	if err := validateSecureFileInfo(pathInfo); err != nil {
		return false, err
	}
	return os.SameFile(opened, pathInfo), nil
}
