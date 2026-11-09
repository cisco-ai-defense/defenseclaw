// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Rolling back an agent file nobody edited since setup puts the saved
// pre-setup bytes back, byte for byte, with one compare-and-swap replace and
// no conversion. A file the operator saved again keeps the merge: only the
// DefenseClaw entries change. A save that lands while the replace runs, or a
// deletion, is the operator own and stays.

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
	out = append(out, 0x0a)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// editorAtomicSave is an editor saving by writing a new file and renaming it
// over the name, which replaces the file instead of changing it.
func editorAtomicSave(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["operator_saved_during_rollback"] = true
	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".editor-save"
	if err := os.WriteFile(tmp, append(out, 0x0a), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func captureRollbackNotes(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := rollbackNoteOutput
	rollbackNoteOutput = &buf
	t.Cleanup(func() { rollbackNoteOutput = previous })
	return &buf
}

// devinSetUp returns a Devin hooks file after setup, with its record published.
func devinSetUp(t *testing.T, name string, pre []byte) (dataDir, path string) {
	t.Helper()
	setHookBinaryOverride(t, devinGuardTestLauncher)
	stubSiblingLauncherGuard(t, true)
	direct := windowsDevinBashHookCommand(devinGuardTestLauncher)
	root := t.TempDir()
	dataDir = filepath.Join(root, "data")
	path = filepath.Join(root, name)
	if err := os.WriteFile(path, pre, 0o600); err != nil {
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
	return dataDir, path
}

func devinRollbackPairs() map[string][][2]string {
	return devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, false)
}

// devinHandlersInEarlierForm counts the handlers of the file in the direct
// form releases before 1.0.9 own.
func devinHandlersInEarlierForm(t *testing.T, path string) int {
	t.Helper()
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	return convertDevinHookForms(devinHooksObject(path, cfg), devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, true), false)
}

func recordExists(dataDir, name, path string) bool {
	_, ok := managedFileBackupFor(dataDir, name, path)
	return ok
}

func TestRollbackPutsBackAnUneditedDevinConfigByteForByte(t *testing.T) {
	for _, variant := range rollbackPristineVariants {
		t.Run(variant.name, func(t *testing.T) {
			notes := captureRollbackNotes(t)
			dataDir, path := devinSetUp(t, "config.json", variant.bytes)
			setUp, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var kept []byte
			keep := func(_, _ string, data []byte) error { kept = data; return nil }
			n, err := convertDevinHooksFile(path, dataDir, "devin", devinRollbackPairs(), true, keep)
			if err != nil || n != 3 {
				t.Fatalf("conversion = %d, %v; want 3 handlers", n, err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, variant.bytes) {
				t.Fatalf("file = %q, want the pre-setup bytes %q", got, variant.bytes)
			}
			if !bytes.Equal(kept, setUp) {
				t.Fatalf("the copy kept before the restore = %q, want the bytes setup wrote", kept)
			}
			if recordExists(dataDir, "devin", path) {
				t.Fatal("the record of a restored file must be removed")
			}
			if !strings.Contains(notes.String(), path) {
				t.Fatalf("the restore is not reported: %q", notes.String())
			}
		})
	}
}

func TestRollbackMergesAnEditedDevinConfigAsBefore(t *testing.T) {
	for _, variant := range rollbackPristineVariants {
		t.Run(variant.name, func(t *testing.T) {
			captureRollbackNotes(t)
			dataDir, path := devinSetUp(t, "config.json", variant.bytes)
			resaveWithOperatorKey(t, path)
			n, err := convertDevinHooksFile(path, dataDir, "devin", devinRollbackPairs(), true, nil)
			if err != nil || n != 3 {
				t.Fatalf("conversion = %d, %v; want 3 handlers", n, err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(got, []byte("operator_after_setup")) || devinHandlersInEarlierForm(t, path) != 3 {
				t.Fatalf("the edited file was not merged: %q", got)
			}
			if !recordExists(dataDir, "devin", path) {
				t.Fatal("an edited file keeps its record")
			}
		})
	}
}

// The restore commits only while the file is still the bytes it read. An editor
// that saves by renaming a new file over the name, at either check, keeps its
// save: it is not replaced by the saved pre-setup bytes.
func TestRollbackKeepsAnAtomicRenameSaveMadeDuringTheRestore(t *testing.T) {
	cases := []struct {
		name string
		hook func(path string, save func()) func()
	}{
		{"before the compare", func(path string, save func()) func() {
			return setAtomicTransformBeforeCompareHookForTest(path, func(attempt int) {
				if attempt == 0 {
					save()
				}
			})
		}},
		{"before the commit", func(path string, save func()) func() {
			return setAtomicTransformBeforeCommitHookForTest(path, func(attempt int) {
				if attempt == 0 {
					save()
				}
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notes := captureRollbackNotes(t)
			dataDir, path := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
			t.Cleanup(tc.hook(path, func() { editorAtomicSave(t, path) }))
			n, err := convertDevinHooksFile(path, dataDir, "devin", devinRollbackPairs(), true, nil)
			if err != nil || n != 3 {
				t.Fatalf("conversion = %d, %v; want 3 handlers", n, err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(got, []byte("operator_saved_during_rollback")) {
				t.Fatalf("the editor save was replaced: %q", got)
			}
			if devinHandlersInEarlierForm(t, path) != 3 {
				t.Fatalf("the DefenseClaw entries of the saved file were not rewritten: %q", got)
			}
			if !recordExists(dataDir, "devin", path) {
				t.Fatal("a file that was not restored keeps its record")
			}
			if !strings.Contains(notes.String(), "WARNING") || !strings.Contains(notes.String(), path) {
				t.Fatalf("the kept save is not reported with the file name: %q", notes.String())
			}
		})
	}
}

func TestRollbackLeavesAFileDeletedDuringTheRestoreDeleted(t *testing.T) {
	notes := captureRollbackNotes(t)
	dataDir, path := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
	t.Cleanup(setAtomicTransformBeforeCompareHookForTest(path, func(attempt int) {
		if attempt == 0 {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		}
	}))
	if _, err := convertDevinHooksFile(path, dataDir, "devin", devinRollbackPairs(), true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the deleted file was recreated (%v)", err)
	}
	if !strings.Contains(notes.String(), "deleted") || !strings.Contains(notes.String(), path) {
		t.Fatalf("the deletion is not reported: %q", notes.String())
	}
}

// An edited file is converted by a compare-and-swap replace too. A save by
// rename, or a deletion, made while the copy of the file is kept is the
// operator own: the conversion starts again from the saved bytes, or leaves the
// deleted file deleted. It never writes the document it read earlier.
func TestRollbackKeepsASaveMadeWhileTheCopyOfAnEditedDevinConfigIsKept(t *testing.T) {
	captureRollbackNotes(t)
	dataDir, path := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
	resaveWithOperatorKey(t, path)
	saved := false
	var kept [][]byte
	keep := func(_, _ string, data []byte) error {
		kept = append(kept, data)
		if !saved {
			saved = true
			editorAtomicSave(t, path)
		}
		return nil
	}
	n, err := convertDevinHooksFile(path, dataDir, "devin", devinRollbackPairs(), true, keep)
	if err != nil || n != 3 {
		t.Fatalf("conversion = %d, %v; want 3 handlers", n, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("operator_saved_during_rollback")) || !bytes.Contains(got, []byte("operator_after_setup")) {
		t.Fatalf("the save made while the copy was kept was overwritten: %q", got)
	}
	if devinHandlersInEarlierForm(t, path) != 3 {
		t.Fatalf("the DefenseClaw entries of the saved file were not rewritten: %q", got)
	}
	if len(kept) != 2 || bytes.Contains(kept[0], []byte("operator_saved_during_rollback")) || !bytes.Contains(kept[1], []byte("operator_saved_during_rollback")) {
		t.Fatalf("the copy kept after the save must hold the saved bytes: %d copies", len(kept))
	}
}

func TestRollbackLeavesAnEditedDevinConfigDeletedWhileTheCopyIsKept(t *testing.T) {
	captureRollbackNotes(t)
	dataDir, path := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
	resaveWithOperatorKey(t, path)
	keep := func(_, _ string, _ []byte) error {
		if _, err := os.Lstat(path); err == nil {
			return os.Remove(path)
		}
		return nil
	}
	n, err := convertDevinHooksFile(path, dataDir, "devin", devinRollbackPairs(), true, keep)
	if err != nil || n != 0 {
		t.Fatalf("conversion = %d, %v; want nothing rewritten", n, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the deleted file was recreated (%v)", err)
	}
}

func TestRollbackConvertsAFileWithoutARecordAsBefore(t *testing.T) {
	captureRollbackNotes(t)
	dataDir, path := devinSetUp(t, "config.json", rollbackPristineVariants[0].bytes)
	discardManagedFileBackup(dataDir, "devin", "config")
	n, err := convertDevinHooksFile(path, dataDir, "devin", devinRollbackPairs(), true, nil)
	if err != nil || n != 3 || devinHandlersInEarlierForm(t, path) != 3 {
		t.Fatalf("conversion = %d, %v; want the three handlers rewritten in place", n, err)
	}
}

func setUpClaudeCodeSettings(t *testing.T, pre []byte) (SetupOpts, *ClaudeCodeConnector, string) {
	t.Helper()
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
	if err := os.WriteFile(settingsPath, pre, 0o600); err != nil {
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
	return opts, c, settingsPath
}

func TestRollbackPutsBackUneditedClaudeCodeSettingsByteForByte(t *testing.T) {
	for _, variant := range rollbackPristineVariants {
		for _, edited := range []bool{false, true} {
			name := variant.name + "/unedited"
			if edited {
				name = variant.name + "/edited"
			}
			t.Run(name, func(t *testing.T) {
				captureRollbackNotes(t)
				opts, c, settingsPath := setUpClaudeCodeSettings(t, variant.bytes)
				if edited {
					resaveWithOperatorKey(t, settingsPath)
				}
				if n, err := c.ConvertHooksForRollback(opts); err != nil || n == 0 {
					t.Fatalf("ConvertHooksForRollback = %d, %v; want a conversion", n, err)
				}
				got, err := os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				if !edited && !bytes.Equal(got, variant.bytes) {
					t.Fatalf("file = %q, want the pre-setup bytes %q", got, variant.bytes)
				}
				if edited && (!bytes.Contains(got, []byte("operator_after_setup")) || !bytes.Contains(got, []byte("hooks"))) {
					t.Fatalf("the edited file was not merged: %q", got)
				}
				if recordExists(opts.DataDir, c.Name(), settingsPath) == !edited {
					t.Fatalf("record present = %v for edited = %v", !edited, edited)
				}
			})
		}
	}
}

func TestRollbackKeepsAClaudeCodeAtomicRenameSaveMadeDuringTheRestore(t *testing.T) {
	notes := captureRollbackNotes(t)
	opts, c, settingsPath := setUpClaudeCodeSettings(t, rollbackPristineVariants[0].bytes)
	t.Cleanup(setAtomicTransformBeforeCommitHookForTest(settingsPath, func(attempt int) {
		if attempt == 0 {
			editorAtomicSave(t, settingsPath)
		}
	}))
	if n, err := c.ConvertHooksForRollback(opts); err != nil || n == 0 {
		t.Fatalf("ConvertHooksForRollback = %d, %v", n, err)
	}
	got, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("operator_saved_during_rollback")) {
		t.Fatalf("the editor save was replaced: %q", got)
	}
	if !strings.Contains(notes.String(), "WARNING") {
		t.Fatalf("the kept save is not reported: %q", notes.String())
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

func TestRollbackPutsBackAnUneditedKiroHooksFileByteForByte(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	const launcher = `C:\Users\dcw std1\.local\bin\defenseclaw-hook.exe`
	pairs := kiroWindowsHookFormPairs([]string{launcher})
	for _, variant := range rollbackPristineVariants {
		for _, edited := range []bool{false, true} {
			name := variant.name + "/unedited"
			if edited {
				name = variant.name + "/edited"
			}
			t.Run(name, func(t *testing.T) {
				captureRollbackNotes(t)
				root := t.TempDir()
				dataDir := filepath.Join(root, "data")
				path := filepath.Join(root, "hooks.json")
				if err := os.WriteFile(path, variant.bytes, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := captureManagedFileBackup(dataDir, "kiro", "hooks", path); err != nil {
					t.Fatal(err)
				}
				installed, err := json.MarshalIndent(map[string]any{
					"operator-note": "pre",
					"hooks":         map[string]any{"preToolUse": []any{map[string]any{"command": pairs[0][0]}}},
				}, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := atomicWriteFile(path, installed, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := updateManagedFileBackupPostHash(dataDir, "kiro", "hooks", path); err != nil {
					t.Fatal(err)
				}
				if edited {
					resaveWithOperatorKey(t, path)
				}
				n, err := convertKiroHooksFile(path, dataDir, "kiro", pairs, true, nil)
				if err != nil || n != 1 {
					t.Fatalf("conversion = %d, %v; want 1 command", n, err)
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !edited && !bytes.Equal(got, variant.bytes) {
					t.Fatalf("file = %q, want the pre-setup bytes %q", got, variant.bytes)
				}
				if edited && (!bytes.Contains(got, []byte("operator_after_setup")) || !bytes.Contains(got, kiroJSONString(pairs[0][1], true))) {
					t.Fatalf("the edited file was not merged: %q", got)
				}
			})
		}
	}
}

func TestRollbackPutsBackAnUneditedCodexConfigByteForByte(t *testing.T) {
	pinWindowsSystemDirectoryForTest(t)
	const launcher = `C:\Users\dcw std1\.local\bin\defenseclaw-hook.exe`
	for _, edited := range []bool{false, true} {
		name := "unedited"
		if edited {
			name = "edited"
		}
		t.Run(name, func(t *testing.T) {
			captureRollbackNotes(t)
			dir := t.TempDir()
			configPath := filepath.Join(dir, "codex", "config.toml")
			dataDir := filepath.Join(dir, "defenseclaw")
			for _, path := range []string{filepath.Dir(configPath), dataDir} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			previousPath := CodexConfigPathOverride
			CodexConfigPathOverride = configPath
			t.Cleanup(func() { CodexConfigPathOverride = previousPath })
			pre := []byte("# operator comment\r\nmodel = \"gpt-5\"")
			if err := os.WriteFile(configPath, pre, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := captureManagedFileBackup(dataDir, "codex", "config.toml", configPath); err != nil {
				t.Fatal(err)
			}
			command, ok := windowsCmdDirectHookCommand(launcher, nativeHookBridgeArguments("codex", "PreToolUse", "codex-hooks-v4", nil))
			if !ok {
				t.Fatal("no direct form")
			}
			installed := fmt.Sprintf("model = \"gpt-5\"\n\n[[hooks.PreToolUse]]\nmatcher = \"*\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = %q\ncommand_windows = %q\ntimeout = 30\n", command, command)
			if err := atomicWriteFile(configPath, []byte(installed), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := updateManagedFileBackupPostHash(dataDir, "codex", "config.toml", configPath); err != nil {
				t.Fatal(err)
			}
			if edited {
				if err := os.WriteFile(configPath, []byte(installed+"# operator_after_setup\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			n, err := convertCodexConfigHookForms(SetupOpts{DataDir: dataDir, HookExecutable: launcher}, true, func(string, []byte) error { return nil })
			if err != nil || n == 0 {
				t.Fatalf("conversion = %d, %v; want a conversion", n, err)
			}
			got, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !edited && !bytes.Equal(got, pre) {
				t.Fatalf("file = %q, want the pre-setup bytes %q", got, pre)
			}
			if edited && !bytes.Contains(got, []byte("operator_after_setup")) {
				t.Fatalf("the edit was lost: %q", got)
			}
		})
	}
}
