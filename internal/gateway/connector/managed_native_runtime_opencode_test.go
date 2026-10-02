// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// On the Windows standalone machine-policy route OpenCode's managed plugin
// runs the hook binary, so its per-user row writes only the managed native
// runtime, exactly like Copilot's. A plugin-only connector (Amp) has none.
func TestManagedNativeHookRuntimeAcceptsOpenCode(t *testing.T) {
	dataDir := t.TempDir()
	if err := ReconcileManagedNativeHookRuntime(dataDir, "127.0.0.1:18970", "opencode", strings.Repeat("a", 64)); err != nil {
		t.Fatalf("write the OpenCode managed runtime: %v", err)
	}
	if err := ValidateManagedNativeHookRuntime(dataDir, "127.0.0.1:18970", "opencode"); err != nil {
		t.Fatalf("validate the OpenCode managed runtime: %v", err)
	}
	if err := ValidateManagedNativeHookRuntime(dataDir, "127.0.0.1:18971", "opencode"); err == nil {
		t.Fatal("a different protected gateway address passed validation")
	}
	for _, name := range []string{"amp", "devin"} {
		if err := ReconcileManagedNativeHookRuntime(t.TempDir(), "127.0.0.1:18970", name, strings.Repeat("a", 64)); err == nil ||
			!strings.Contains(err.Error(), "unsupported managed native hook connector") {
			t.Fatalf("%s must have no managed native runtime: %v", name, err)
		}
	}
}
