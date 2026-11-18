// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peversion

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// StringValue returns the first translation's string value name (for
// example "ProductVersion" or "FileVersion") from the version resource of
// the PE file at path.
func StringValue(path, name string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", fmt.Errorf("read the version resource size of %s: %w", path, err)
	}
	if size == 0 || size > 1<<20 {
		return "", fmt.Errorf("the version resource of %s has an unexpected size %d", path, size)
	}
	buffer := make([]byte, size)
	defer runtime.KeepAlive(buffer)
	block := unsafe.Pointer(&buffer[0])
	if err := windows.GetFileVersionInfo(path, 0, size, block); err != nil {
		return "", fmt.Errorf("read the version resource of %s: %w", path, err)
	}
	within := func(pointer unsafe.Pointer, bytes uintptr) bool {
		start := uintptr(block)
		at := uintptr(pointer)
		return pointer != nil && at >= start && at-start <= uintptr(len(buffer)) &&
			bytes <= uintptr(len(buffer))-(at-start)
	}
	var translation unsafe.Pointer
	var length uint32
	if err := windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&translation), &length); err != nil {
		return "", fmt.Errorf("read the version translation of %s: %w", path, err)
	}
	if length < 4 || !within(translation, 4) {
		return "", fmt.Errorf("the version resource of %s has no translation", path)
	}
	language := *(*uint16)(translation)
	codePage := *(*uint16)(unsafe.Add(translation, 2))
	var value unsafe.Pointer
	length = 0
	key := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, language, codePage, name)
	if err := windows.VerQueryValue(block, key, unsafe.Pointer(&value), &length); err != nil {
		return "", fmt.Errorf("read the %s of %s: %w", name, path, err)
	}
	if length == 0 || length > 256 || !within(value, uintptr(length)*2) {
		return "", fmt.Errorf("the %s of %s is missing or malformed", name, path)
	}
	return strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(value), length))), nil
}
