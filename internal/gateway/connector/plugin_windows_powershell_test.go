// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A Windows installed outside C:\Windows (D:\WINNT here) has no
// C:\Windows\System32 PowerShell. The per-user Amp and OpenCode plugins check
// the native helper's owner and DACL with PowerShell before every gateway
// call; launching a hard-coded C:\Windows copy failed that check, so both
// plugins blocked every tool call with a trusted helper and a healthy
// gateway. Setup must render the PowerShell of the system directory it
// resolved with GetSystemDirectoryW, and verification must repair a plugin
// that still hard-codes the path.
func TestPerUserPluginsRunPowerShellFromTheResolvedSystemDirectory(t *testing.T) {
	saved := windowsSystemDirectory
	windowsSystemDirectory = func() string { return `D:\WINNT\System32\` }
	t.Cleanup(func() { windowsSystemDirectory = saved })
	powershell := javaScriptStringContent(`D:\WINNT\System32\WindowsPowerShell\v1.0\powershell.exe`)
	const call = `execFileSync(DC_WINDOWS_POWERSHELL, [`
	const hardCoded = `execFileSync("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", [`
	for _, tc := range []struct {
		name, pluginName, declaration string
	}{
		{"opencode", "defenseclaw.js", `const DC_WINDOWS_POWERSHELL = "` + powershell + `";` + "\n"},
		{"amp", "defenseclaw.ts", `const DC_WINDOWS_POWERSHELL: string = "` + powershell + `"` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			pluginPath := filepath.Join(root, ".config", tc.name, "plugins", tc.pluginName)
			var conn Connector
			opts := SetupOpts{DataDir: filepath.Join(root, "defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: "scoped-test-token"}
			if tc.name == "opencode" {
				old := OpenCodePluginPathOverride
				OpenCodePluginPathOverride = pluginPath
				t.Cleanup(func() { OpenCodePluginPathOverride = old })
				conn = NewOpenCodeConnector()
				opts = prepareOpenCodeSetupOptsForTest(t, opts)
			} else {
				old := AMPPluginPathOverride
				AMPPluginPathOverride = pluginPath
				t.Cleanup(func() { AMPPluginPathOverride = old })
				conn = NewAMPConnector()
				opts = prepareAmpSetupOptsForTest(t, opts)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatal(err)
			}
			installed := string(data)
			if !strings.Contains(installed, `const DC_PER_USER_NATIVE_POST`) || strings.Count(installed, tc.declaration) != 1 {
				t.Fatalf("per-user %s plugin does not name the resolved system PowerShell %s", tc.name, powershell)
			}
			if strings.Count(installed, call) != 1 || strings.Contains(installed, `C:\\Windows`) {
				t.Fatalf("per-user %s plugin does not launch the resolved PowerShell for the helper ACL check", tc.name)
			}
			if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
				t.Fatalf("new plugin did not verify: present=%v err=%v", present, err)
			}
			legacy := strings.Replace(installed, call, hardCoded, 1)
			if err := os.WriteFile(pluginPath, []byte(legacy), 0o600); err != nil {
				t.Fatal(err)
			}
			if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
				t.Fatalf("plugin that hard-codes C:\\Windows was accepted: present=%v err=%v", present, err)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
				t.Fatalf("Setup did not repair the plugin: present=%v err=%v", present, err)
			}
		})
	}
}
