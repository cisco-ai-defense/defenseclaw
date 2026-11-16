// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// serveUnenrolledRefusals runs the refusal pipe of the Windows standalone
// managed gateway (unenrolled_refusal_audit.go) until ctx ends. Other
// profiles, Secure Client included, do not serve it. A failure only loses
// refusal rows; it never affects the API.
func (a *APIServer) serveUnenrolledRefusals(ctx context.Context) {
	if _, ok := standaloneManagedServiceAccount(); !ok {
		return
	}
	runUnenrolledRefusalAudit(ctx, func(ctx context.Context, auditor *unenrolledRefusalAuditor) {
		logged := false
		for ctx.Err() == nil {
			err := refusalpipe.Serve(ctx, auditor.record)
			if err != nil && !logged {
				// Another process holding the name, or the previous API run
				// still closing its instances: retry without repeating the line.
				fmt.Fprintf(os.Stderr, "[sidecar-api] unenrolled-account refusal pipe unavailable, retrying: %v\n", err)
				logged = true
			}
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}, a.auditUnenrolledRefusal)
}
