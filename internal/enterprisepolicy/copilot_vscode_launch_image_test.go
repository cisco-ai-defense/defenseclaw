// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0601: the Local hook file DefenseClaw 1.0.9 wrote names the transition
// image bin\defenseclaw-hook.exe. With the 1.0.10 launch image as the hook
// binary it read as a foreign hook file: the guardian left it in place,
// claimed no Local coverage for a signed-in account and failed the upgrade.
// It is DefenseClaw's own render of the same install and is rewritten; a
// render for another install's bin stays foreign.
func TestCopilotVSCodeLaunchImageOwnsThe109TransitionRender(t *testing.T) {
	const transition = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	const launch = `C:\Program Files\Cisco\DefenseClaw\bin\hooks\95265bb3041675a9\defenseclaw-hook.exe`
	released, err := os.ReadFile(filepath.Join("testdata", "copilot-vscode-1.0.9", "windows-hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The bridge starts powershell.exe from the system directory the host
	// reports, as 1.0.9 did on dc-ent-win.
	exe, _, _ := strings.Cut(connector.CopilotVSCodeLocalManagedHookCommand("windows", transition, "Stop"), " -NoLogo")
	released = bytes.ReplaceAll(released, []byte(`C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe`),
		[]byte(strings.ReplaceAll(exe, `\`, `\\`)))

	for _, tc := range []struct {
		name    string
		binary  string
		foreign bool
	}{
		{"launch image of the same bin", launch, false},
		{"the transition image itself", transition, false},
		{"launch image of another install", `D:\Other\DefenseClaw\bin\hooks\95265bb3041675a9\defenseclaw-hook.exe`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeFile(t, CopilotVSCodeLocalHookFilePath(home), string(released))
			check, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{Home: home, GOOS: "windows", HookBinary: tc.binary, HookFile: true, DryRun: true})
			if err != nil {
				t.Fatal(err)
			}
			kept := slices.Contains(check.Kept, CopilotVSCodeLocalHookFilePath(home))
			if kept != tc.foreign {
				t.Fatalf("kept=%t, want foreign=%t: %+v", kept, tc.foreign, check)
			}
			if tc.foreign {
				return
			}
			if _, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{Home: home, GOOS: "windows", HookBinary: tc.binary, HookFile: true}); err != nil {
				t.Fatal(err)
			}
			want, err := RenderCopilotVSCodeLocalHooks("windows", tc.binary)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(CopilotVSCodeLocalHookFilePath(home))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
				t.Fatalf("the 1.0.9 file was not rewritten for %s", tc.binary)
			}
		})
	}
}

func TestDecodePowerShellEncodedCommand(t *testing.T) {
	// "dir" as UTF-16LE, base64.
	if got, ok := decodePowerShellEncodedCommand(`powershell.exe -NoLogo -EncodedCommand ZABpAHIA`); !ok || got != "dir" {
		t.Fatalf("decoded %q %t", got, ok)
	}
	for _, command := range []string{"powershell.exe -EncodedCommand", "powershell.exe -EncodedCommand !!", "cmd.exe /c dir", "powershell.exe -EncodedCommand ZABpAHI"} {
		if got, ok := decodePowerShellEncodedCommand(command); ok {
			t.Fatalf("%q decoded as %q", command, got)
		}
	}
}

// rel-1-0-10 GAP-0794: before a downgrade to 1.0.9, `hook-image retire`
// makes every writer name the transition image, so the guardian rewrites
// the Local hook file for it. 1.0.9 owns only its own exact render, so this
// release must render, for the transition image, the very bytes 1.0.9
// wrote (testdata: the file 1.0.9 left on dc-ent-win); otherwise the 1.0.9
// guardian keeps the file as foreign, fails the account and the downgrade.
func TestCopilotVSCodeTransitionRenderIsThe109Render(t *testing.T) {
	const transition = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	released, err := os.ReadFile(filepath.Join("testdata", "copilot-vscode-1.0.9", "windows-hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	exe, _, _ := strings.Cut(connector.CopilotVSCodeLocalManagedHookCommand("windows", transition, "Stop"), " -NoLogo")
	released = bytes.ReplaceAll(released, []byte(`C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe`),
		[]byte(strings.ReplaceAll(exe, `\`, `\\`)))
	got, err := RenderCopilotVSCodeLocalHooks("windows", transition)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(released)) {
		t.Fatalf("the transition render is not the 1.0.9 render:\n%s\nwant\n%s", got, released)
	}
}
