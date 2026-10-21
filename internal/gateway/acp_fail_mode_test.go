// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Review fix (r103): an observe-mode verdict carries the profile's explicit
// fail_mode either way, so the guard enforces an explicit closed; action
// mode is always closed and carries none.
func TestACPProfileFailMode(t *testing.T) {
	for _, tc := range []struct{ failMode, mode, want string }{
		{"open", "observe", "open"},
		{" Closed ", "observe", "closed"},
		{"", "observe", ""},
		{"closed", "action", ""},
		{"bogus", "observe", ""},
	} {
		if got := acpProfileFailMode(config.ACPProfile{FailMode: tc.failMode}, tc.mode); got != tc.want {
			t.Errorf("acpProfileFailMode(%q, %q) = %q, want %q", tc.failMode, tc.mode, got, tc.want)
		}
	}
}
