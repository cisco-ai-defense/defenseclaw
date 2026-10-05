// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The native hook accepts exactly the surface marker Setup renders.
func TestKiroRenderedSurfaceIsTheOneTheHookAccepts(t *testing.T) {
	if !hookexec.HookSurfaceAllowed("kiro", KiroHookSurfaceV3) {
		t.Fatalf("hook binary rejects the %q marker Setup renders", KiroHookSurfaceV3)
	}
	if hookexec.HookSurfaceAllowed("kiro", KiroHookSurfaceV2) {
		t.Fatalf("hook binary accepts %q, which Setup never renders", KiroHookSurfaceV2)
	}
}
