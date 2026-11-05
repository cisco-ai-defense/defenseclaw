// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"context"
	"log/slog"
)

// discoveryReader: only the Linux (Cowork VM) helper serves discovery reads.
func discoveryReader([]string, *slog.Logger) func(context.Context) (any, error) { return nil }
