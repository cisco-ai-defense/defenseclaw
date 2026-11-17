// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kitspec

import (
	"maps"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// GAP-0447: the harness base environment the allowlist test checks is the
// one openshell records for the pinned base image.
func TestPinnedBaseEnvIsTheOpenShellRecord(t *testing.T) {
	if !maps.Equal(pinnedBaseEnv, openshell.DefaultBaseImageEnv) {
		t.Fatalf("pinnedBaseEnv %v differs from openshell.DefaultBaseImageEnv %v", pinnedBaseEnv, openshell.DefaultBaseImageEnv)
	}
}
