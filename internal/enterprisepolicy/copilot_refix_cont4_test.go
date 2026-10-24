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
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestCopilotMalformedLocalHookIsRepairedWithoutIndependentHandlers(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, broken := range []string{
			`{`,
			`{"hooks":false}`,
			`{"hooks":[]}`,
			`{"hooks":{"PreToolUse":"broken"}}`,
		} {
			t.Run(goos+"/"+broken, func(t *testing.T) {
				binary := testHookBinary
				if goos == "windows" {
					binary = `C:\DefenseClaw\defenseclaw-hook.exe`
				}
				home := t.TempDir()
				path := CopilotVSCodeLocalHookFilePath(home)
				req := CopilotVSCodeUserRequest{Home: home, GOOS: goos, HookBinary: binary, HookFile: true}
				if _, err := EnsureCopilotVSCodeUser(req); err != nil {
					t.Fatal(err)
				}
				writeFile(t, path, broken)
				req.DryRun = true
				if result, err := EnsureCopilotVSCodeUser(req); err != nil || !slices.Contains(result.Changed, path) || slices.Contains(result.Kept, path) {
					t.Fatalf("verify did not report repairable damage: %+v, %v", result, err)
				}
				req.DryRun = false
				if result, err := EnsureCopilotVSCodeUser(req); err != nil || !result.HookFileOK || slices.Contains(result.Kept, path) {
					t.Fatalf("reconcile did not repair its Local hook: %+v, %v", result, err)
				}
				want, err := RenderCopilotVSCodeLocalHooks(goos, binary)
				if err != nil || readFile(t, path) != string(want) {
					t.Fatalf("reconcile did not publish current hooks: %v", err)
				}
				writeFile(t, path, broken)
				req.HookFile = false
				if result, err := EnsureCopilotVSCodeUser(req); err != nil || !slices.Contains(result.Removed, path) {
					t.Fatalf("removal left malformed own hook: %+v, %v", result, err)
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("malformed own hook survived removal: %v", err)
				}
			})
		}
	}

	home := t.TempDir()
	path := CopilotVSCodeLocalHookFilePath(home)
	const independent = `{"hooks":{"PreToolUse":[{"type":"command","command":"operator-tool"}],"PostToolUse":"broken"}}`
	writeFile(t, path, independent)
	for _, keep := range []bool{true, false} {
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: keep})
		if err != nil || !slices.Contains(result.Kept, path) || readFile(t, path) != independent {
			t.Fatalf("independent handler changed: %+v, %v", result, err)
		}
	}

	for _, destination := range []struct {
		name string
		path string
		file bool
	}{
		{"Local", CopilotVSCodeLocalHookFilePath(home), true},
		{"plugin", CopilotPluginHooksPath(home), false},
	} {
		t.Run(destination.name+" independent root", func(t *testing.T) {
			const malformed = `{"version":1,"hooks":false,"operator":{"enabled":true}}`
			writeFile(t, destination.path, malformed)
			req := CopilotVSCodeUserRequest{Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: destination.file, Plugin: !destination.file}
			if result, err := EnsureCopilotVSCodeUser(req); err != nil || slices.Contains(result.Kept, destination.path) {
				t.Fatalf("repair dropped a parseable independent root: %+v, %v", result, err)
			}
			var repaired map[string]any
			if err := json.Unmarshal([]byte(readFile(t, destination.path)), &repaired); err != nil {
				t.Fatal(err)
			}
			if repaired["operator"] == nil || repaired["hooks"] == nil {
				t.Fatalf("repair lost a root key or the managed hooks: %v", repaired)
			}
			writeFile(t, destination.path, malformed)
			req.HookFile, req.Plugin = false, false
			if _, err := EnsureCopilotVSCodeUser(req); err != nil {
				t.Fatal(err)
			}
			var remaining map[string]any
			if err := json.Unmarshal([]byte(readFile(t, destination.path)), &remaining); err != nil {
				t.Fatal(err)
			}
			if remaining["operator"] == nil || remaining["hooks"] != nil {
				t.Fatalf("removal did not keep only the independent root: %v", remaining)
			}
		})
	}
}

func TestCopilotPublishedCorruptionDoesNotReplaceRemovalPreimage(t *testing.T) {
	for _, original := range []string{"", `{"version":1,"hooks":{"operatorEvent":[{"type":"command","bash":"operator-tool"}]}}`} {
		for _, broken := range []string{"", `{`, `{"hooks":false}`, `{"hooks":{"preToolUse":"broken"}}`} {
			t.Run(original+"/"+broken, func(t *testing.T) {
				opts := copilotRefixOptions(t)
				opts.CopilotCLIPolicyOnly = true
				path := copilotDropIn(t, opts)
				if original != "" {
					writeFile(t, path, original)
				}
				target := copilotTarget{}
				if state, err := target.Reconcile(opts); err != nil || !state.Covered {
					t.Fatalf("initial publication: %+v, %v", state, err)
				}
				writeFile(t, path, broken)
				if state, err := target.Reconcile(opts); err != nil || !state.Covered {
					t.Fatalf("repair after publication: %+v, %v", state, err)
				}
				if _, err := target.RemoveOwned(opts); err != nil {
					t.Fatal(err)
				}
				if original == "" {
					if _, err := os.Lstat(platformPath(opts, path)); !os.IsNotExist(err) {
						t.Fatalf("removed policy restored corrupt bytes: %v", err)
					}
				} else if got := readFile(t, platformPath(opts, path)); got != original {
					t.Fatalf("removal lost original administrator policy: %s", got)
				}
			})
		}
	}
	for _, original := range []string{"", `{"version":1,"hooks":{"operatorEvent":[{"type":"command","bash":"operator-tool"}]}}`} {
		t.Run("independent root/"+original, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("the fixture uses a Unix handler; Windows is covered by the other corruption cases")
			}
			opts := copilotRefixOptions(t)
			opts.CopilotCLIPolicyOnly = true
			path := copilotDropIn(t, opts)
			if original != "" {
				writeFile(t, path, original)
			}
			target := copilotTarget{}
			if _, err := target.Reconcile(opts); err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, `{"hooks":false,"operator":{"enabled":true}}`)
			if state, err := target.Reconcile(opts); err != nil || !state.Covered {
				t.Fatalf("repair lost coverage: %+v, %v", state, err)
			}
			if _, err := target.RemoveOwned(opts); err != nil {
				t.Fatal(err)
			}
			var restored map[string]any
			if err := json.Unmarshal([]byte(readFile(t, path)), &restored); err != nil {
				t.Fatal(err)
			}
			if restored["operator"] == nil {
				t.Fatalf("independent root content was removed: %v", restored)
			}
			if original != "" && restored["hooks"].(map[string]any)["operatorEvent"] == nil {
				t.Fatalf("preexisting independent handler was removed: %v", restored)
			}
		})
	}
}

func TestCopilotBinaryChangeReplacesRecordedHandlerOnly(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			if goos == "windows" && runtime.GOOS != "windows" {
				t.Skip("Windows policy file I/O requires native Windows")
			}
			if runtime.GOOS == "windows" && goos != "windows" {
				t.Skip("Unix policy file I/O requires a Unix host")
			}
			opts := copilotRefixOptions(t)
			opts.GOOS = goos
			opts.CopilotCLIPolicyOnly = true
			path := copilotDropIn(t, opts)
			field := "bash"
			if goos == "windows" {
				field = "powershell"
			}
			another := opts
			if goos == "windows" {
				another.HookBinary = `C:\Operator\defenseclaw-hook.exe`
			} else {
				another.HookBinary = "/opt/operator/defenseclaw-hook"
			}
			otherRendered, err := renderCopilotDropIn(another)
			if err != nil {
				t.Fatal(err)
			}
			var otherDoc map[string]any
			if err := json.Unmarshal(otherRendered, &otherDoc); err != nil {
				t.Fatal(err)
			}
			otherHandler := otherDoc["hooks"].(map[string]any)["preToolUse"].([]any)[0]
			initial, err := json.Marshal(map[string]any{"version": 1, "hooks": map[string]any{"preToolUse": []any{
				map[string]any{"type": "command", field: "operator-tool"}, otherHandler,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			independent := string(initial)
			writeFile(t, path, independent)
			target := copilotTarget{}
			if state, err := target.Reconcile(opts); err != nil || !state.Covered {
				t.Fatalf("initial publication: %+v, %v", state, err)
			}
			previous := opts
			opts.HookBinary = filepath.Join(filepath.Dir(opts.HookBinary), "replacement", filepath.Base(opts.HookBinary))
			if goos == "windows" {
				opts.HookBinary = `C:\Replacement\defenseclaw-hook.exe`
			}
			if state, err := target.Verify(opts); err != nil || state.Covered {
				t.Fatalf("verify accepted the old binary: %+v, %v", state, err)
			}
			if state, err := target.Reconcile(opts); err != nil || !state.Covered {
				t.Fatalf("binary change did not repair coverage: %+v, %v", state, err)
			}
			data := readFile(t, platformPath(opts, path))
			var doc map[string]any
			if err := json.Unmarshal([]byte(data), &doc); err != nil {
				t.Fatal(err)
			}
			hooks := doc["hooks"].(map[string]any)
			for event, raw := range hooks {
				entries := raw.([]any)
				wantCount := 1
				if event == "preToolUse" {
					wantCount = 3
				}
				if len(entries) != wantCount {
					t.Fatalf("%s has %d handlers after rotation, want %d: %s", event, len(entries), wantCount, data)
				}
				for _, entry := range entries {
					if copilotHandlerIsOwned(previous, entry) {
						t.Fatalf("old binary remains active in %s: %s", event, data)
					}
				}
			}
			if _, err := target.RemoveOwned(opts); err != nil {
				t.Fatal(err)
			}
			if got := readFile(t, platformPath(opts, path)); got != independent {
				t.Fatalf("removal changed the independent handler: %s", got)
			}
		})
	}
}

func TestCopilotBinaryChangeRecognizesRecordedPreGuardCommand(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			previous := Options{GOOS: goos, HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook"}
			field := "bash"
			if goos == "windows" {
				previous.HookBinary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
				previous.WindowsProgramData = `C:\ProgramData`
				previous.WindowsProgramFiles = `C:\Program Files`
				field = "powershell"
			}
			published, err := renderCopilotDropIn(previous)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(published, &doc); err != nil {
				t.Fatal(err)
			}
			for _, raw := range doc["hooks"].(map[string]any) {
				handler := raw.([]any)[0].(map[string]any)
				command := handler[field].(string)
				if goos == "windows" {
					command = strings.Replace(command, connector.CopilotRemovedDeploymentGuardPowerShell(previous.HookBinary)+"; ", "", 1)
				} else {
					command = strings.TrimPrefix(command, connector.CopilotRemovedDeploymentGuardPOSIX(previous.HookBinary))
				}
				handler[field] = command
			}
			prior, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			current := previous
			if goos == "windows" {
				current.HookBinary = `C:\Replacement\defenseclaw-hook.exe`
			} else {
				current.HookBinary = "/opt/replacement/defenseclaw-hook"
			}
			const ownedPath = "recorded-copilot-drop-in"
			record := &ownershipRecord{Path: ownedPath, PostimageSHA256: sha256Hex(prior)}
			merged, err := mergeCopilotDropInWithRecord(current, prior, record, ownedPath)
			want, wantErr := renderCopilotDropIn(current)
			if err != nil || wantErr != nil || string(merged) != string(want) {
				t.Fatalf("binary rotation kept the prior release command: %s, %v, %v", merged, err, wantErr)
			}
			unrecorded, err := mergeCopilotDropIn(current, prior)
			if err != nil || string(unrecorded) == string(want) {
				t.Fatalf("an unrecorded command was claimed as ours: %s, %v", unrecorded, err)
			}
		})
	}
}
