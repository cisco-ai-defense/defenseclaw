// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Rolling back an agent file nobody edited since setup puts the saved
// pre-setup bytes back, byte for byte. The rollback first rewrites the hook
// entries into the form the earlier release owns; that write is DefenseClaw's
// own, so it must not make the file look edited. A file the operator saved
// again since setup keeps the merge: the entries go, the operator's bytes stay.

var rollbackPristineVariants = []struct {
	name  string
	bytes []byte
}{
	{"compact JSON", []byte(`{"operator-note":"pre"}`)},
	{"CRLF", []byte("{\r\n  \"operator-note\": \"pre\"\r\n}\r\n")},
	{"no trailing newline", []byte("{\n  \"operator-note\": \"pre\"\n}")},
}

// resaveWithOperatorKey is an editor saving the file again with a key of its
// own: the same document, re-serialized, plus one operator entry.
func resaveWithOperatorKey(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["operator_after_setup"] = true
	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDevinRollbackConversionKeepsExactRestoreOfUneditedConfig(t *testing.T) {
	setHookBinaryOverride(t, devinGuardTestLauncher)
	stubSiblingLauncherGuard(t, true)
	direct := windowsDevinBashHookCommand(devinGuardTestLauncher)
	toEarlier := devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, false)
	toCurrent := devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, true)
	for _, variant := range rollbackPristineVariants {
		for _, edited := range []bool{false, true} {
			name := variant.name + "/unedited"
			if edited {
				name = variant.name + "/edited"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				dataDir := filepath.Join(root, "data")
				path := filepath.Join(root, "config.json")
				if err := os.WriteFile(path, variant.bytes, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := captureManagedFileBackup(dataDir, "devin", "config", path); err != nil {
					t.Fatal(err)
				}
				if err := patchDevinHooksForEvents(path, func(event string) string {
					return devinHookCommandForEvent("windows", SetupOpts{}, direct, event)
				}); err != nil {
					t.Fatal(err)
				}
				if err := updateManagedFileBackupPostHash(dataDir, "devin", "config", path); err != nil {
					t.Fatal(err)
				}
				if edited {
					resaveWithOperatorKey(t, path)
				}
				if n, err := convertDevinHooksFile(path, dataDir, "devin", toEarlier, true, nil); err != nil || n != 3 {
					t.Fatalf("conversion = %d, %v; want 3 handlers", n, err)
				}
				if !edited {
					// An aborted rollback and a second attempt leave the exact restore on.
					if n, err := convertDevinHooksFile(path, dataDir, "devin", toCurrent, false, nil); err != nil || n != 3 {
						t.Fatalf("undo = %d, %v; want 3 handlers", n, err)
					}
					if n, err := convertDevinHooksFile(path, dataDir, "devin", toEarlier, true, nil); err != nil || n != 3 {
						t.Fatalf("second conversion = %d, %v; want 3 handlers", n, err)
					}
				}
				restored, err := restoreManagedFileBackupIfUnchanged(dataDir, "devin", "config", path)
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if restored == edited {
					t.Fatalf("exact restore = %v for edited = %v (file %q)", restored, edited, got)
				}
				if !edited && !bytes.Equal(got, variant.bytes) {
					t.Fatalf("restored file = %q, want %q", got, variant.bytes)
				}
				if edited && !bytes.Contains(got, []byte("operator_after_setup")) {
					t.Fatalf("the operator edit was lost: %q", got)
				}
			})
		}
	}
}

func TestClaudeCodeRollbackConversionKeepsExactRestoreOfUneditedSettings(t *testing.T) {
	for _, variant := range rollbackPristineVariants {
		for _, edited := range []bool{false, true} {
			name := variant.name + "/unedited"
			if edited {
				name = variant.name + "/edited"
			}
			t.Run(name, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "Ana Lima")
				opts := SetupOpts{
					DataDir:        filepath.Join(dir, ".defenseclaw"),
					HookExecutable: filepath.Join(dir, ".local", "bin", "defenseclaw-hook.exe"),
				}
				hooksDir := filepath.Join(opts.DataDir, "hooks")
				if err := os.MkdirAll(hooksDir, 0o700); err != nil {
					t.Fatal(err)
				}
				settingsPath := filepath.Join(dir, ".claude", "settings.json")
				ClaudeCodeSettingsPathOverride = settingsPath
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })
				pinClaudeCodePreToolGuard(t, filepath.Join(dir, "Programs", "DefenseClaw", "bin", "defenseclaw-hook.exe"))
				if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(settingsPath, variant.bytes, 0o600); err != nil {
					t.Fatal(err)
				}
				c := NewClaudeCodeConnector()
				if err := captureManagedFileBackup(opts.DataDir, c.Name(), "settings.json", settingsPath); err != nil {
					t.Fatal(err)
				}
				command, args := claudeCodeHookInvocation(opts, filepath.Join(hooksDir, "claude-code-hook.sh"))
				hooks := map[string]interface{}{}
				appendClaudeCodeHookMatrix(hooks, command, args)
				installed, err := json.MarshalIndent(map[string]interface{}{"operator-note": "pre", "hooks": hooks}, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				// Setup writes through the atomic writer, whose commit the record trusts.
				if err := atomicWriteFile(settingsPath, installed, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "settings.json", settingsPath); err != nil {
					t.Fatal(err)
				}
				if edited {
					resaveWithOperatorKey(t, settingsPath)
				}
				if n, err := c.ConvertHooksForRollback(opts); err != nil || n == 0 {
					t.Fatalf("ConvertHooksForRollback = %d, %v; want a conversion", n, err)
				}
				restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), "settings.json", settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				if restored == edited {
					t.Fatalf("exact restore = %v for edited = %v (file %q)", restored, edited, got)
				}
				if !edited && !bytes.Equal(got, variant.bytes) {
					t.Fatalf("restored file = %q, want %q", got, variant.bytes)
				}
				if edited && !bytes.Contains(got, []byte("operator_after_setup")) {
					t.Fatalf("the operator edit was lost: %q", got)
				}
			})
		}
	}
}

// Cursor has no conversion: a rollback restores a file that still holds what
// setup wrote, whatever shape the pre-setup bytes had, and keeps an edit.
func TestCursorRollbackRestoresUneditedHooksFileExactly(t *testing.T) {
	for _, variant := range rollbackPristineVariants {
		for _, edited := range []bool{false, true} {
			name := variant.name + "/unedited"
			if edited {
				name = variant.name + "/edited"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				t.Setenv("HOME", root)
				t.Setenv("USERPROFILE", root)
				dataDir := filepath.Join(root, "data")
				target := filepath.Join(root, ".cursor", "hooks.json")
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, variant.bytes, 0o600); err != nil {
					t.Fatal(err)
				}
				opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
				if err := NewCursorConnector().Setup(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				if edited {
					resaveWithOperatorKey(t, target)
				}
				restored, _, err := RestoreManagedFileBackupsForRollback(dataDir, filepath.Join(root, "older-data"), root, map[string]bool{}, "")
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				if (len(restored) == 1) == edited {
					t.Fatalf("restored = %v for edited = %v (file %q)", restored, edited, got)
				}
				if !edited && !bytes.Equal(got, variant.bytes) {
					t.Fatalf("restored file = %q, want %q", got, variant.bytes)
				}
				if edited && !bytes.Contains(got, []byte("operator_after_setup")) {
					t.Fatalf("the operator edit was lost: %q", got)
				}
			})
		}
	}
}
