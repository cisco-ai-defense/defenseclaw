// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
)

// A write tool call's CodeGuard scan reads only the call's arguments, and the
// rule dispatch does not read its result, so the two run at the same time.
// Run one after the other they added up: a benign 1 MB Write spent about
// 0.5 s in CodeGuard after about 0.7 s in the rule passes on a fast host,
// and on a loaded Windows host the sum ran past the hook's 3.5 s answer
// budget, so the call was closed as "did not answer in time" (GAP-2284).
// The verdict is built from both results exactly as before.

// inspectCodeGuardArgs and inspectDispatchTrustedAction are the two scans of
// inspectTrustedToolPolicyCtx. Variables so a test can observe that they
// overlap.
var (
	inspectCodeGuardArgs = func(a *APIServer, ctx context.Context, req *ToolInspectRequest) codeGuardArgsScan {
		return a.runCodeGuardOnArgsWithProvenance(ctx, req)
	}
	inspectDispatchTrustedAction = dispatchTrustedAction
)

// startCodeGuardOnArgs starts the CodeGuard scan of req and returns the wait
// for its result. A panic in the scan is raised again by the wait, on the
// caller's goroutine, so the hook's panic recovery sees it as before.
func (a *APIServer) startCodeGuardOnArgs(ctx context.Context, req *ToolInspectRequest) func() codeGuardArgsScan {
	done := make(chan struct{})
	var scan codeGuardArgsScan
	var panicked any
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		scan = inspectCodeGuardArgs(a, ctx, req)
	}()
	return func() codeGuardArgsScan {
		<-done
		if panicked != nil {
			panic(panicked)
		}
		return scan
	}
}
