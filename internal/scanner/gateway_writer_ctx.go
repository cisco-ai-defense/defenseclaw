// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

type gatewayWriterCtxKey struct{}

// ContextWithGatewayWriter attaches a gateway JSONL writer for subprocess
// error emissions. Optional — nil is a no-op for EventError fan-out.
func ContextWithGatewayWriter(ctx context.Context, w *gatewaylog.Writer) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithValue(ctx, gatewayWriterCtxKey{}, w)
}

func gatewayWriterFromContext(ctx context.Context) *gatewaylog.Writer {
	if ctx == nil {
		return nil
	}
	w, _ := ctx.Value(gatewayWriterCtxKey{}).(*gatewaylog.Writer)
	return w
}
