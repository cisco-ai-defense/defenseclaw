// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
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
			for _, legacy := range []struct{ name, body string }{
				{"hard-codes C:\\Windows", strings.Replace(installed, call, hardCoded, 1)},
				// A plugin whose ACL check does not insist on the script's
				// own report (one that still runs cmdlets PSModulePath
				// resolves) is repaired too.
				{"passes the ACL check without the script's report", strings.Replace(installed, windowsHelperACLCheckMarker, "if (false)", 1)},
			} {
				if legacy.body == installed {
					t.Fatalf("legacy variant %q did not change the plugin", legacy.name)
				}
				if err := os.WriteFile(pluginPath, []byte(legacy.body), 0o600); err != nil {
					t.Fatal(err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
					t.Fatalf("plugin that %s was accepted: present=%v err=%v", legacy.name, present, err)
				}
				if err := conn.Setup(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
					t.Fatalf("Setup did not repair the plugin that %s: present=%v err=%v", legacy.name, present, err)
				}
			}
		})
	}
}

// PowerShell finds a cmdlet through PSModulePath, which the agent's
// environment sets. A module planted in a folder it names first can export
// ConvertFrom-Json or Get-Acl, answer "nothing to check", and so pass the
// per-user plugins' Windows helper owner/DACL check for a helper another
// account may replace. The rendered check must call no cmdlet at all, launch
// PowerShell with PSModulePath reset to the system PowerShell's own module
// folder and without a .NET profiler, and pass only when the script itself
// reports every entry checked (a check that exits 0 without doing the work
// fails). The native run is TestWindowsPerUserPluginRejectsWritableHelperPaths.
func TestPerUserPluginHelperACLCheckCallsNoCmdlet(t *testing.T) {
	cmdlet := regexp.MustCompile(`\b[A-Z][A-Za-z]+-[A-Z][A-Za-z]+\b`)
	function := regexp.MustCompile(`function \w*[cC]heckWindowsHelperACL\(`)
	for _, asset := range []string{"opencode-plugin.js", "amp-plugin.ts"} {
		t.Run(asset, func(t *testing.T) {
			body := renderPluginAssetForTest(t, asset, templateData{
				TokenFileJS:         javaScriptStringContent(`C:\Users\dev\.defenseclaw\hooks\.token`),
				WindowsPowerShellJS: javaScriptStringContent(`D:\WINNT\System32\WindowsPowerShell\v1.0\powershell.exe`),
			})
			loc := function.FindStringIndex(body)
			if loc == nil {
				t.Fatal("rendered per-user plugin has no Windows helper ACL check")
			}
			check := body[loc[0]:]
			check = check[:strings.Index(check, "\n}\n")+3]
			start := strings.Index(check, "const script = [")
			end := strings.Index(check, "].join(")
			if start < 0 || end < start {
				t.Fatalf("ACL check has no PowerShell script:\n%s", check)
			}
			if found := cmdlet.FindAllString(check[start:end], -1); len(found) > 0 {
				t.Errorf("ACL script calls cmdlets PSModulePath resolves: %v", found)
			}
			for _, want := range []string{
				`env.PSModulePath = join(dirname(DC_WINDOWS_POWERSHELL), "Modules")`,
				`/^(psmodulepath|psmoduleanalysiscachepath|cor_|complus_)/i.test(name)`,
				`execFileSync(DC_WINDOWS_POWERSHELL, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]`,
				"env, timeout: 5000",
				windowsHelperACLCheckMarker,
			} {
				if strings.Count(check, want) != 1 {
					t.Errorf("ACL check lacks %q", want)
				}
			}
		})
	}
}
