// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux && !darwin

package connector

import (
	"fmt"
	"os"
)

func atomicTransformOpenFileIdentity(file *os.File) (string, error) {
	return "", fmt.Errorf("stable file identity is unsupported on this platform: %s", file.Name())
}

func atomicTransformDirectoryIdentity(path string) (string, error) {
	return "", fmt.Errorf("stable directory identity is unsupported on this platform: %s", path)
}
