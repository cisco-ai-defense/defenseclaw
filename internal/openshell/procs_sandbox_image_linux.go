// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package openshell

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func sandboxDaemonProcessPath(ctx context.Context, pid int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if pid <= 0 {
		return "", fmt.Errorf("invalid process pid %d", pid)
	}
	path, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", err
	}
	path = strings.TrimSuffix(path, " (deleted)")
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("process image for pid %d has no absolute path", pid)
	}
	return path, nil
}
