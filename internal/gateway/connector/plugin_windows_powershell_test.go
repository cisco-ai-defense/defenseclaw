// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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

// rel-1-0-6 GAP-0025: the per-user plugins' helper ACL check called every
// failure an untrusted owner or DACL, a PowerShell that took longer than the
// 5 s budget to start included. Only an owner or another writer the script
// found keeps that refusal; a timeout, a PowerShell that does not start, a
// path that went away and any other script failure name their own cause and
// next step. Every case still refuses the call. A POSIX stand-in plays the
// system PowerShell; the native run is
// TestWindowsPerUserPluginRejectsWritableHelperPaths.
func TestPerUserPluginHelperACLCheckNamesItsOwnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a POSIX shell script stands in for PowerShell")
	}
	node := nodeForTest(t)
	dir := testenv.PrivateTempDir(t)
	fake := filepath.Join(dir, "powershell")
	script := "#!/bin/sh\ncat >/dev/null\ncase \"$DC_FAKE_ACL\" in\n" +
		"  slow) sleep 8 ;;\n" +
		"  owner|writable|missing) printf 'failed %s' \"$DC_FAKE_ACL\"; exit 3 ;;\n" +
		"  other) printf 'failed Attempted to perform an unauthorized operation.'; exit 3 ;;\n" +
		"  short) printf 'checked 1' ;;\n" +
		"  *) printf 'checked 2' ;;\n" +
		"esac\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	const dacl = "per-user gateway helper path has an untrusted Windows owner or DACL"
	cases := []struct{ name, powershell, want string }{
		{"ok", fake, "allowed"},
		{"owner", fake, dacl},
		{"writable", fake, dacl},
		{"short", fake, dacl},
		{"slow", fake, "the per-user gateway helper ACL check did not finish within 5 s (Windows PowerShell was slow to start); retry the call"},
		{"missing", fake, "a per-user gateway helper path went missing during its ACL check"},
		{"other", fake, "the per-user gateway helper ACL check failed (Attempted to perform an unauthorized operation.); retry the call"},
		{"absent", filepath.Join(dir, "no-powershell"), "did not start for the per-user gateway helper ACL check (ENOENT); run defenseclaw doctor"},
	}
	extract := func(t *testing.T, body, name string) string {
		t.Helper()
		start := strings.Index(body, "function "+name+"(")
		if start < 0 {
			t.Fatalf("rendered plugin has no %s", name)
		}
		fn := body[start:]
		return fn[:strings.Index(fn, "\n}\n")+3]
	}
	for _, tc := range []struct{ asset, module, check, failure, constant string }{
		{"opencode-plugin.js", "acl.mjs", "defenseclawCheckWindowsHelperACL", "defenseclawWindowsACLCheckFailure", "let DC_WINDOWS_POWERSHELL = \"\";"},
		{"amp-plugin.ts", "acl.mts", "checkWindowsHelperACL", "windowsACLCheckFailure", "let DC_WINDOWS_POWERSHELL: string = \"\""},
	} {
		t.Run(tc.asset, func(t *testing.T) {
			body := renderPluginAssetForTest(t, tc.asset, templateData{
				TokenFileJS:         javaScriptStringContent(`C:\Users\dev\.defenseclaw\hooks\.token`),
				WindowsPowerShellJS: javaScriptStringContent(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
			})
			module := "import { execFileSync } from \"node:child_process\"\nimport { dirname, join } from \"node:path\"\n" +
				tc.constant + "\nexport function setPowerShell(path" + map[bool]string{true: ": string", false: ""}[strings.HasSuffix(tc.module, ".mts")] + ") { DC_WINDOWS_POWERSHELL = path }\n" +
				"export " + extract(t, body, tc.check) + extract(t, body, tc.failure)
			modulePath := filepath.Join(t.TempDir(), tc.module)
			if err := os.WriteFile(modulePath, []byte(module), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					harness := "const m = await import(process.argv[1]); m.setPowerShell(process.argv[2]); process.env.DC_FAKE_ACL = process.argv[3];" +
						"try { m." + tc.check + "([\"/x\"]); console.log(\"allowed\") } catch (error) { console.log(error.message) }"
					ctx, cancel := context.WithTimeout(context.Background(), nodeHarnessTimeout)
					defer cancel()
					out, err := exec.CommandContext(ctx, node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", harness, modulePath, c.powershell, c.name).CombinedOutput()
					if err != nil {
						t.Fatalf("node: %v\n%s", err, out)
					}
					got := strings.TrimSpace(string(out))
					if !strings.Contains(got, c.want) {
						t.Fatalf("%s: got %q, want it to contain %q", c.name, got, c.want)
					}
					if c.want != dacl && strings.Contains(got, "DACL") {
						t.Fatalf("%s: a non-ACL failure still reads as a DACL refusal: %q", c.name, got)
					}
				})
			}
		})
	}
}
