// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "context"

type exportOnlyInCallKey struct{}

// WithExportOnlyInCall marks an occurrence whose facts the hook call that
// emits it already stores in its own row of record (the hook_decision
// record of the call): while that call write batch is open the runtime
// writes nothing locally for it and sends it to the remote destinations after
// the call commits, as it sends every record of the call (commit before
// export at the granularity of the call). Outside an open call batch it is
// written locally as any record. Producers set it in code; it is not a config
// key (#1384, bar H1: one local row per decision).
func WithExportOnlyInCall(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, exportOnlyInCallKey{}, true)
}

// WithExportAfterCallCommit marks an occurrence whose export waits for its
// hook call's writes to commit and is dropped when they did not: the
// hook_decision record that is the only local row of a benign per-user
// decision. When its row cannot be written the call answers with its
// fail-mode verdict and exports a new decision record that carries it, so an
// export never holds a verdict the agent did not get (#1384). Other records
// keep GAP-1536: exported also when the local store is down.
func WithExportAfterCallCommit(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, exportAfterCallCommitKey{}, true)
}

// ExportAfterCallCommit reports whether ctx carries WithExportAfterCallCommit.
func ExportAfterCallCommit(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(exportAfterCallCommitKey{}).(bool)
	return marked
}

type exportAfterCallCommitKey struct{}

// ExportOnlyInCall reports whether ctx carries WithExportOnlyInCall.
func ExportOnlyInCall(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(exportOnlyInCallKey{}).(bool)
	return marked
}
