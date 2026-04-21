// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// EmitSubprocessExitFromContext emits EventError for a non-zero subprocess
// exit when a gateway writer is present on the context.
func EmitSubprocessExitFromContext(ctx context.Context, scannerBinary string, exitCode int, stderr string) {
	EmitSubprocessExitEvent(gatewayWriterFromContext(ctx), scannerBinary, exitCode, stderr)
}

// EmitSubprocessExitEvent writes a structured SUBPROCESS_EXIT error.
func EmitSubprocessExitEvent(w *gatewaylog.Writer, scannerBinary string, exitCode int, stderr string) {
	if w == nil {
		return
	}
	w.Emit(gatewaylog.Event{
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(gatewaylog.SubsystemScanner),
			Code:      string(gatewaylog.ErrCodeSubprocessExit),
			Message:   fmt.Sprintf("%s exited with code %d", scannerBinary, exitCode),
			Cause:     stderr,
		},
	})
}
