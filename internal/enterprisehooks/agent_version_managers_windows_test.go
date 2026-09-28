// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
)

// npm CLIs installed through nvm-windows, fnm, Volta, pnpm or a custom
// .npmrc prefix were never found on Windows, so the user got no row.
func TestStandaloneWindowsDiscoveryFindsVersionManagerInstalls(t *testing.T) {
	stubMachineWinGet(t, nil)
	codex := filepath.Join("@openai", "codex")
	for name, layout := range map[string]func(home string) string{
		"nvm-windows": func(home string) string {
			writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "nvm", "v20.1.0", "node_modules", codex), "0.140.0")
			return filepath.Join(home, "AppData", "Roaming", "nvm", "v22.11.0", "node_modules", codex)
		},
		"fnm": func(home string) string {
			return filepath.Join(home, "AppData", "Roaming", "fnm", "node-versions", "v22.3.0", "installation", "node_modules", codex)
		},
		"volta": func(home string) string {
			return filepath.Join(home, "AppData", "Local", "Volta", "tools", "image", "packages", codex, "node_modules", codex)
		},
		"pnpm": func(home string) string {
			return filepath.Join(home, "AppData", "Local", "pnpm", "global", "5", "node_modules", codex)
		},
		"npmrc": func(home string) string {
			if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte("fund=false\r\nprefix=${USERPROFILE}\\tools\\npm\r\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(home, "tools", "npm", "node_modules", codex)
		},
	} {
		home := t.TempDir()
		writeWindowsAgentPackageJSON(t, layout(home), "0.150.0")
		if got, reason := standaloneWindowsAgentVersionExplain(home, "codex"); got != "0.150.0" {
			t.Errorf("%s: codex version = %q (%s), want the newest install 0.150.0", name, got, reason)
		}
		// The Secure Client probes stay the fixed list.
		if got, _ := windowsAgentVersionExplain(home, "codex"); got != "" {
			t.Errorf("%s: the shared (Secure Client) probe found %q", name, got)
		}
	}

	// A .npmrc prefix outside the profile is not the user's own install.
	home := t.TempDir()
	outside := t.TempDir()
	writeWindowsAgentPackageJSON(t, filepath.Join(outside, "node_modules", codex), "0.150.0")
	if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte("prefix="+outside+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := standaloneWindowsAgentVersionExplain(home, "codex"); got != "" {
		t.Fatalf("a prefix outside the profile was read: %q", got)
	}
}
