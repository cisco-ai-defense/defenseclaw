// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"os/exec"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

func newCodexAppServerCommand(ctx context.Context, executable string) *exec.Cmd {
	return processutil.CommandContext(ctx, executable, "app-server", "--stdio")
}
