// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The standalone guardian verifies each target first and re-renders it only
// when verification fails. Verification must therefore require the
// foreign-hook guard line in the Amp and OpenCode plugins: a plugin rendered
// before the guard existed, or edited to drop it, fails Verify and the next
// install renders the guard.
func TestVerifyRequiresTheForeignHookGuardInStandalonePlugins(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	const guard = "/opt/defenseclaw/bin/defenseclaw-hook"
	for _, tc := range []struct {
		name, declaration, terminator, agentVersion string
	}{
		{name: "amp", declaration: "const DC_FOREIGN_GUARD: string = ", terminator: "\n", agentVersion: "0.0.1785334225"},
		{name: "opencode", declaration: "const DC_FOREIGN_GUARD = ", terminator: ";\n", agentVersion: "opencode 1.18.11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := connector.AMPPluginPathOverride
			connector.AMPPluginPathOverride = ""
			t.Cleanup(func() { connector.AMPPluginPathOverride = previous })
			ctx := context.Background()
			opts := InstallOptions{
				ConnectorName: tc.name,
				UserHome:      newTestHome(t),
				OwnerUID:      os.Getuid(),
				OwnerGID:      os.Getgid(),
				APIAddr:       "127.0.0.1:18970",
				ProxyAddr:     "127.0.0.1:4000",
				APIToken:      strings.Repeat("a", 64),
				GuardrailMode: "action",
				HookFailMode:  "closed",
				AgentVersion:  tc.agentVersion,
				Registry:      connector.NewDefaultRegistry(),
			}
			// A plugin rendered before the guard existed.
			result, err := Install(ctx, opts)
			if err != nil {
				t.Fatalf("Install without the guard: %v", err)
			}
			if len(result.HookConfigPaths) != 1 {
				t.Fatalf("plugin paths = %v", result.HookConfigPaths)
			}
			plugin := result.HookConfigPaths[0]
			if _, err := Verify(ctx, opts); err != nil {
				t.Fatalf("the unguarded render verifies for an unguarded install: %v", err)
			}
			guarded := opts
			guarded.ForeignHookGuardBinary = guard
			if _, err := Verify(ctx, guarded); err == nil {
				t.Fatal("a plugin without the guard line must fail standalone verification")
			}

			guarded.AllowMissingHookConfigRepair = true
			if _, err := Install(ctx, guarded); err != nil {
				t.Fatalf("repair with the guard: %v", err)
			}
			body, err := os.ReadFile(plugin)
			if err != nil {
				t.Fatal(err)
			}
			line := tc.declaration + `"` + guard + `"` + tc.terminator
			if !strings.Contains(string(body), line) {
				t.Fatalf("the repaired plugin must carry %q", line)
			}
			if _, err := Verify(ctx, guarded); err != nil {
				t.Fatalf("the guarded render verifies: %v", err)
			}

			// A user edit that drops the guard fails verification again.
			edited := strings.Replace(string(body), line, tc.declaration+`""`+tc.terminator, 1)
			if err := os.WriteFile(plugin, []byte(edited), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, guarded); err == nil {
				t.Fatal("a plugin edited to drop the guard must fail verification")
			}
		})
	}
}
