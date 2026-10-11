//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
)

// startEnterpriseHookQuarantineRemovals is Windows only: a Linux or macOS
// managed gateway does not watch enrolled users' folders.
func startEnterpriseHookQuarantineRemovals(context.Context, io.Writer) {}
