// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A registry the administrator's setting left inactive answers the Codex hook
// as an unregistered account, which Secure Client delivers open, with the
// setting in the reason. Any other inactive or active registry is unchanged.
func TestWindowsCodexAdminConflictRuntimeErrorIsUnregisteredAndNamed(t *testing.T) {
	conflict := "allow_managed_hooks_only=false conflicts with required DefenseClaw managed-hook isolation"
	err := windowsCodexAdminConflictRuntimeError(connector.WindowsCodexManagedRuntimeRegistry{
		AdminConflict: conflict,
	})
	if err == nil {
		t.Fatal("administrator conflict gave no hook runtime error")
	}
	if class := WindowsManagedRuntimeFailureClassOf(err); class != WindowsManagedRuntimeFailureUnregistered {
		t.Fatalf("class = %q, want %q", class, WindowsManagedRuntimeFailureUnregistered)
	}
	if !strings.Contains(err.Error(), conflict) {
		t.Fatalf("reason %q does not name the setting", err)
	}
	if err := windowsCodexAdminConflictRuntimeError(connector.WindowsCodexManagedRuntimeRegistry{}); err != nil {
		t.Fatalf("inactive registry without a conflict = %v, want nil", err)
	}
	if err := windowsCodexAdminConflictRuntimeError(connector.WindowsCodexManagedRuntimeRegistry{
		Active:        true,
		AdminConflict: conflict,
	}); err != nil {
		t.Fatalf("active registry = %v, want nil", err)
	}
}
