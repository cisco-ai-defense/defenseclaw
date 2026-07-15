// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func launcherWorkingDirectories(installRoot string) (logical, process string, err error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	logical, err = winpath.Extended(cwd)
	if err != nil {
		return "", "", err
	}
	volume := filepath.VolumeName(filepath.Clean(installRoot))
	if volume == "" {
		return "", "", fmt.Errorf("install root has no Windows volume: %s", installRoot)
	}
	// CreateProcessW validates lpCurrentDirectory before the child runs and can
	// reject a >MAX_PATH repository even in extended form. Start Python from the
	// short root of the install volume, then chdir inside Python using the exact
	// extended caller directory passed as an argv value (never shell text).
	return logical, volume + string(os.PathSeparator), nil
}
