// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestBuildHookOptionsEnterpriseManagedCarriesForeignHookPolicy(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "open")
	userRuntime := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(userRuntime, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{
			Connector:            "cursor",
			DataDir:              userRuntime,
			PolicyActive:         true,
			Registered:           true,
			GatewayAddr:          "127.0.0.1:18977",
			GatewayServiceName:   "DefenseClawGateway",
			ScopedToken:          "authenticated-generation-token",
			GenerationID:         "0123456789abcdef0123456789abcdef",
			ApprovedForeignHooks: a + "," + b,
		}, nil
	})
	if enterpriseManagedHookRuntimeNoop("cursor") {
		t.Fatal("registered enterprise runtime was treated as a no-op")
	}
	opts := buildHookOptionsForRuntime("cursor", "", "", "", true)
	if len(opts.ApprovedForeignHooks) != 2 || opts.ApprovedForeignHooks[0] != a || opts.ApprovedForeignHooks[1] != b {
		t.Fatalf("approved foreign hooks = %v", opts.ApprovedForeignHooks)
	}
	if !sameWindowsHookPath(opts.ForeignHookTrustedExecutable, nativeHookExecutable()) {
		t.Fatalf("trusted executable = %q, want %q", opts.ForeignHookTrustedExecutable, nativeHookExecutable())
	}
	if !sameWindowsHookPath(opts.ForeignHookProfileHome, filepath.Dir(userRuntime)) {
		t.Fatalf("profile home = %q, want %q", opts.ForeignHookProfileHome, filepath.Dir(userRuntime))
	}

	// An unverified runtime never contributes an allowlist.
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{
			Connector:            "cursor",
			PolicyActive:         true,
			ApprovedForeignHooks: a,
		}, os.ErrPermission
	})
	if enterpriseManagedHookRuntimeNoop("cursor") {
		t.Fatal("failed enterprise runtime was treated as a no-op")
	}
	opts = buildHookOptionsForRuntime("cursor", "", "", "", true)
	if len(opts.ApprovedForeignHooks) != 0 || opts.ForeignHookTrustedExecutable != "" || opts.ForeignHookProfileHome != "" {
		t.Fatalf(
			"failed runtime leaked foreign hook policy: %v %q %q",
			opts.ApprovedForeignHooks,
			opts.ForeignHookTrustedExecutable,
			opts.ForeignHookProfileHome,
		)
	}
}
