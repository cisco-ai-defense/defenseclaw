// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package openshell

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/procimage"
)

// sandboxDaemonProcessPath obtains the process image path through the one
// kernel call the repository makes for it (procimage.Path, the same
// interface as libproc's proc_pidpath). It works without cgo.
func sandboxDaemonProcessPath(ctx context.Context, pid int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if pid <= 0 {
		return "", fmt.Errorf("invalid process pid %d", pid)
	}
	path, err := procimage.Path(pid)
	if err != nil {
		return "", fmt.Errorf("process image for pid %d: %w", pid, err)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("process image for pid %d has no absolute path", pid)
	}
	return path, nil
}
