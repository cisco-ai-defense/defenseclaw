// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedEveryRegisteredConnectorUsesOpenDefault(t *testing.T) {
	registry := NewDefaultRegistry()
	for _, name := range registry.Names() {
		conn, ok := registry.Get(name)
		if !ok {
			t.Fatal(name)
		}
		for _, configured := range []string{"", "open", "closed"} {
			opts := SetupOpts{ManagedEnterprise: true, HookFailMode: configured, CodexEnforcement: true, ClaudeCodeEnforcement: true}
			if got := resolveHookFailMode(opts, conn); got != "open" {
				t.Errorf("connector=%s configured=%q got=%q, want open", name, configured, got)
			}
			if hookOnly, ok := conn.(*hookOnlyConnector); ok && hookOnly.effectiveFailClosed(opts) {
				t.Errorf("connector=%s still writes a fail-closed client setting", name)
			}
		}
		t.Logf("connector=%s enterprise default=open", name)
	}
}

func TestManagedOpenCursorAdapterHandlesLauncherFailures(t *testing.T) {
	t.Run("missing-launcher", func(t *testing.T) {
		adapter := renderCursorAdapterForTest(t, filepath.Join(t.TempDir(), "missing.exe"), ManagedEnterpriseHookFailMode, true, 1_000)
		stdout, stderr, code := runCursorAdapterTest(t, adapter, `{}`)
		if code != 0 {
			t.Fatalf("exit=%d stderr=%q", code, stderr)
		}
		assertCursorAllowJSON(t, stdout)
	})
	t.Run("launcher-timeout", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(cursorAdapterHelperMode, "timeout")
		adapter := renderCursorAdapterForTest(t, executable, ManagedEnterpriseHookFailMode, true, 1_000)
		stdout, stderr, code := runCursorAdapterTest(t, adapter, `{}`)
		if code != 0 || !strings.Contains(stderr, "timed out") {
			t.Fatalf("exit=%d stderr=%q", code, stderr)
		}
		assertCursorAllowJSON(t, stdout)
	})
	t.Run("explicit-policy-block", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(cursorAdapterHelperMode, "block")
		adapter := renderCursorAdapterForTest(t, executable, ManagedEnterpriseHookFailMode, true, 1_000)
		stdout, stderr, code := runCursorAdapterTest(t, adapter, `{}`)
		if code != 2 || !strings.Contains(stdout, `"continue":false`) {
			t.Fatalf("policy block lost: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
}
