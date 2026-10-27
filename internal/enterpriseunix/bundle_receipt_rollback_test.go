// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-1205: a bundle receipt states only what the gateway proved. A failed
// apply whose rollback put the last good files back while the gateway still
// reports another policy (it kept the candidate) is failed, not rolled_back,
// and names the policy the gateway reports.
func TestFailedBundleIsRolledBackOnlyWithGatewayProof(t *testing.T) {
	for _, c := range afterWriteCases() {
		t.Run(c.name(), func(t *testing.T) {
			b, version, cfg := c.start(t)
			good := b.read(b.env.Layout.ConfigPath)
			kept := "sha256:" + strings.Repeat("e", 64)
			original := b.env.HealthGet
			left := false
			b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
				installed := b.read(b.env.Layout.ConfigPath)
				left = left || installed != good
				if left && installed == good {
					// The files are back; the gateway still enforces
					// another policy.
					b.frozen = kept
				}
				return original(ctx)
			}
			setLifecycleTestFault(t, b.testHost, testFaultAfterServices)
			b.mapPromotedBundleOwners(version)
			r := b.apply(b.dir(version, cfg))
			requireError(t, r, string(enterprisebundle.CodeApplyFailed))
			if !hasWarning(r, codeRolledBack) {
				t.Fatalf("the transaction did not restore the previous files: %+v", r.Warnings)
			}
			rc := b.receipt(bundleID(version))
			if rc.State != enterprisebundle.StateFailed || rc.RolledBack || rc.EnforcingDigest != kept {
				t.Fatalf("receipt = %+v, want failed, not rolled back, enforcing %s", rc, kept)
			}
			if b.read(b.env.Layout.ConfigPath) != good {
				t.Fatal("config.yaml is not the last good config after the failed apply")
			}
		})
	}
}
