// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

type callTargetMemoKey struct{}

// withCallTargetMemo gives the evaluations of one hook call one file system
// memory (hookpaths.NewTargetMemoIn): the sandbox shell reading and the
// trusted tool reading of a call each resolved every distinct word of the
// command again (rel-1-0-10:GAP-0299). A context that has one keeps it.
func withCallTargetMemo(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if callTargetMemo(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, callTargetMemoKey{}, hookpaths.NewCallTargetMemo())
}

// callTargetMemo is the file system memory of the call ctx judges (nil:
// none).
func callTargetMemo(ctx context.Context) *hookpaths.TargetMemo {
	if ctx == nil {
		return nil
	}
	memo, _ := ctx.Value(callTargetMemoKey{}).(*hookpaths.TargetMemo)
	return memo
}
