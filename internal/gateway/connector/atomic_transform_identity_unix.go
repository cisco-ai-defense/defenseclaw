// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package connector

import (
	"fmt"
	"os"
	"syscall"
)

func atomicTransformOpenFileIdentity(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("unsupported stat identity for %s", file.Name())
	}
	return fmt.Sprintf("unix:%d:%d", uint64(stat.Dev), uint64(stat.Ino)), nil
}

func atomicTransformDirectoryIdentity(path string) (string, error) {
	directory, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer directory.Close()
	return atomicTransformOpenFileIdentity(directory)
}
