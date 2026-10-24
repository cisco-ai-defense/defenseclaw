// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package processutil

import (
	"context"
	"os/exec"
)

func RunTreeIsolated(_ context.Context, cmd *exec.Cmd) error { return RunTree(cmd) }
