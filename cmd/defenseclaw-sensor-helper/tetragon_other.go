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
	"fmt"
	"io"
	"log/slog"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// Tetragon runs on Linux only. Managed macOS and Windows accept the
// enterprise.tetragon block and ignore it; these stubs keep the helper's
// other files portable.

func kernelPolicyIntent(kernelpolicy.Lookup, *slog.Logger) kernelpolicy.Intent {
	return kernelpolicy.Intent{Mode: kernelpolicy.ModeOff}
}

func kernelPolicyStart(context.Context, *slog.Logger, kernelpolicy.Lookup, kernelpolicy.DialFunc, string) *kernelpolicy.Controller {
	return nil
}

func kernelPolicyCleanup(_ context.Context, _ *slog.Logger, out io.Writer, _ kernelpolicy.Dirs,
	_ kernelpolicy.DialFunc, _ bool) int {
	fmt.Fprintln(out, "tetragon-cleanup: not applicable on this platform")
	return 0
}
