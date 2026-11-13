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

// ExportOnlyInCall reports whether ctx carries WithExportOnlyInCall.
func ExportOnlyInCall(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(exportOnlyInCallKey{}).(bool)
	return marked
}
