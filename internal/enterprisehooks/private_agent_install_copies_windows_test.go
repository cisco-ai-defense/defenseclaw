//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The runner's own Node installation must not leak into the scan's
// results; a test that needs a machine prefix sets it.
func init() { windowsPrivateInstallMachineRoots = func() []string { return nil } }

func windowsInstallFacts(t *testing.T, install PrivateAgentInstall) map[string]any {
	t.Helper()
	data, err := json.Marshal(install)
	if err != nil {
		t.Fatal(err)
	}
	facts := map[string]any{}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

func windowsClaudeCopy(t *testing.T, dir, version, entry string) {
	t.Helper()
	writeWindowsAgentPackageJSON(t, dir, version)
	if entry == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, entry)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, entry), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Every copy a profile can run is judged once, wherever it was installed:
// the native npm entry point, every installed Node of a version manager,
// the machine npm prefix; a supported install alone reports nothing
// (GAP-0890, GAP-0891, GAP-0892).
func TestDiscoverWindowsPrivateInstallsCoverEveryCopyLayout(t *testing.T) {
	claude := filepath.Join("node_modules", "@anthropic-ai", "claude-code")
	cases := []struct {
		name  string
		build func(t *testing.T, home, machine string)
		want  []string
	}{
		{
			name: "healthy: supported native npm copies report nothing",
			build: func(t *testing.T, home, machine string) {
				windowsClaudeCopy(t, filepath.Join(home, "AppData", "Roaming", "npm", claude), "2.1.230", `bin\claude.exe`)
				windowsClaudeCopy(t, filepath.Join(machine, claude), "2.1.230", `bin\claude.exe`)
			},
		},
		{
			name: "old native npm entry point without cli.js",
			build: func(t *testing.T, home, _ string) {
				windowsClaudeCopy(t, filepath.Join(home, "AppData", "Roaming", "npm", claude), "2.1.230", `bin\claude.exe`)
				windowsClaudeCopy(t, filepath.Join(home, "private", claude), "2.1.150", `bin\claude.exe`)
			},
			want: []string{`claudecode 2.1.150 \private\node_modules\@anthropic-ai\claude-code`},
		},
		{
			name: "package record without an entry point is a leftover",
			build: func(t *testing.T, home, _ string) {
				windowsClaudeCopy(t, filepath.Join(home, "private", claude), "2.0.77", "")
			},
		},
		{
			name: "old copy in the machine npm prefix",
			build: func(t *testing.T, home, machine string) {
				windowsClaudeCopy(t, filepath.Join(home, "AppData", "Roaming", "npm", claude), "2.1.230", `bin\claude.exe`)
				windowsClaudeCopy(t, filepath.Join(machine, claude), "2.0.77", "cli.js")
			},
			want: []string{`claudecode 2.0.77 MACHINE\node_modules\@anthropic-ai\claude-code`},
		},
		{
			name: "nvm-windows link as the machine prefix is read through its profile, not reported incomplete",
			build: func(t *testing.T, home, machine string) {
				target := filepath.Join(home, "AppData", "Roaming", "nvm", "v20.1.0")
				windowsClaudeCopy(t, filepath.Join(target, claude), "2.1.230", `bin\claude.exe`)
				if err := os.RemoveAll(machine); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command("cmd", "/c", "mklink", "/J", machine, target).CombinedOutput(); err != nil {
					t.Fatalf("mklink /J: %v: %s", err, out)
				}
			},
		},
		{
			name: "old copy in the 17th of 17 nvm versions",
			build: func(t *testing.T, home, _ string) {
				for minor := 0; minor < 17; minor++ {
					version, entry := "2.1.230", `bin\claude.exe`
					if minor == 0 {
						version, entry = "2.0.77", "cli.js"
					}
					windowsClaudeCopy(t, filepath.Join(home, "AppData", "Roaming", "nvm", fmt.Sprintf("v20.%d.0", minor), claude), version, entry)
				}
			},
			want: []string{`claudecode 2.0.77 \AppData\Roaming\nvm\v20.0.0\node_modules\@anthropic-ai\claude-code`},
		},
		{
			name: "more Node versions than the bound is incomplete, not dropped",
			build: func(t *testing.T, home, _ string) {
				for minor := 0; minor <= privateAgentInstallMaxVersionDirs; minor++ {
					if err := os.MkdirAll(filepath.Join(home, "AppData", "Local", "fnm", "node-versions", fmt.Sprintf("v18.%d.0", minor), "installation"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			},
			want: []string{"claudecode incomplete " + PrivateInstallSkippedVersionManagers},
		},
		{
			name: "one copy reached through two spellings of a prefix is one copy",
			build: func(t *testing.T, home, _ string) {
				windowsClaudeCopy(t, filepath.Join(home, "AppData", "Roaming", "npm", claude), "2.0.77", "cli.js")
				if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte(`prefix=%USERPROFILE%\appdata\roaming\NPM`+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{`claudecode 2.0.77 \AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			machine := filepath.Join(t.TempDir(), "nodejs")
			if err := os.MkdirAll(machine, 0o755); err != nil {
				t.Fatal(err)
			}
			previous := windowsPrivateInstallMachineRoots
			windowsPrivateInstallMachineRoots = func() []string { return []string{machine} }
			t.Cleanup(func() { windowsPrivateInstallMachineRoots = previous })
			tc.build(t, home, machine)
			var got []string
			for _, install := range DiscoverWindowsPrivateAgentInstalls(home, []string{"claudecode"}) {
				if install.Incomplete {
					skipped, _ := windowsInstallFacts(t, install)["skipped"].(string)
					got = append(got, install.Connector+" incomplete "+skipped)
					continue
				}
				path := strings.Replace(install.Path, machine, "MACHINE", 1)
				got = append(got, install.Connector+" "+install.Version+" "+strings.TrimPrefix(path, home))
			}
			sort.Strings(got)
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("copies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// A supported npm copy must not hide an old WinGet install the version
// probe never reaches.
func TestManagedWindowsReportsOldWinGetCopyBesideSupportedInstall(t *testing.T) {
	stubMachineWinGet(t, map[string]string{"Anthropic.ClaudeCode": "2.0.77"})
	home := t.TempDir()
	windowsClaudeCopy(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code"), "2.1.230", `bin\claude.exe`)
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	var uncovered []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("claudecode"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { uncovered = append(uncovered, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].AgentVersion != "2.1.230" {
		t.Fatalf("supported install lost its row: %+v", manifest.Targets)
	}
	if len(uncovered) != 1 || uncovered[0].Version != "2.0.77" || !strings.Contains(uncovered[0].InstallPath, "WinGet Anthropic.ClaudeCode (machine scope)") {
		t.Fatalf("old WinGet copy = %+v", uncovered)
	}
}
