// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package openshell

import (
	"context"
	"fmt"
)

func sandboxDaemonProcessPath(ctx context.Context, pid int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("process image lookup unavailable for pid %d", pid)
}
