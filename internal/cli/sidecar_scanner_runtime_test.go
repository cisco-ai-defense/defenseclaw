// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"
)

// GAP-0490: the gateway refuses to start before any subsystem when its
// scanner runtime fails the trust check.
func TestSidecarRefusesToStartOnAnUntrustedScannerRuntime(t *testing.T) {
	previous := sidecarScannerRuntimeStartProblem
	t.Cleanup(func() { sidecarScannerRuntimeStartProblem = previous })
	calls := 0
	sidecarScannerRuntimeStartProblem = func() error {
		calls++
		return errors.New("the gateway does not start on the untrusted scanner runtime")
	}
	// cfg is never read: the refusal comes first.
	err := runSidecar(nil, nil)
	if calls != 1 || err == nil || !strings.Contains(err.Error(), "does not start on the untrusted scanner runtime") {
		t.Fatalf("runSidecar = %v after %d checks, want the start refusal", err, calls)
	}
}
