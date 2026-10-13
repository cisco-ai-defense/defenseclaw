//go:build !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
)

// Tetragon runs on Linux only. Managed macOS and Windows accept the
// enterprise.tetragon block and ignore it; main reaches neither stub there.

func startKernelPolicy(context.Context, *slog.Logger, []string, string) *acquire.TetragonConfig {
	return nil
}

func cleanupKernelPolicy(context.Context, io.Writer, *slog.Logger) error { return nil }
