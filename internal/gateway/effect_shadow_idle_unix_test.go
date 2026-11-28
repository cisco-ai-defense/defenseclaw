// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// setParentStepIsTextIdle is the *Idle wrapper of the parent-step switch. Its
// only caller does not build on Windows, so it sits in a !windows file of its
// own: on Windows the unused-function lint has nothing to flag. The GAP-1913
// guard (effect_shadow_idle_test.go) allows exactly this file name next to the
// wrapper file itself.
func setParentStepIsTextIdle(t testing.TB, text bool) func() {
	t.Helper()
	return idleOverride(t, func() func() { return hookpaths.SetParentStepIsText(text) })
}
