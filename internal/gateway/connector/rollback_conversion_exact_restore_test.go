// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// devinProjectSetUp returns a Devin project file (hooks.v1.json) after setup,
// with its record published.
func devinProjectSetUp(t *testing.T) (dataDir, root, path string, pre []byte) {
	t.Helper()
	setHookBinaryOverride(t, devinGuardTestLauncher)
	stubSiblingLauncherGuard(t, true)
	direct := windowsDevinBashHookCommand(devinGuardTestLauncher)
	root = t.TempDir()
	dataDir = filepath.Join(root, "data")
	path = filepath.Join(root, "hooks.v1.json")
	pre = []byte(`{"operator-note":"pre"}`)
	if err := os.WriteFile(path, pre, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(dataDir, "devin", "project", path); err != nil {
		t.Fatal(err)
	}
	if err := patchDevinHooksForEvents(path, func(event string) string {
		return devinHookCommandForEvent("windows", SetupOpts{}, direct, event)
	}); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(dataDir, "devin", "project", path); err != nil {
		t.Fatal(err)
	}
	return dataDir, root, path, pre
}

// The Devin converter reads the project file, keeps a copy, and its writer
// reads the file again to splice only the entries of DefenseClaw. An editor
// does not take the lock of the converter, so a save can land in between. That
// save must stay out of the exact restore; the same conversion over a file
// nobody touched keeps it.
func TestDevinProjectRollbackConversionHonoursAnEditMadeWhileItRuns(t *testing.T) {
	toEarlier := devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, false)
	comment := []byte("// operator note added during rollback\n")
	for _, edited := range []bool{false, true} {
		name := "untouched"
		if edited {
			name = "edit during the copy"
		}
		t.Run(name, func(t *testing.T) {
			dataDir, root, path, pre := devinProjectSetUp(t)
			keep := func(_, _ string, _ []byte) error { return nil }
			if edited {
				keep = func(_, _ string, _ []byte) error {
					old, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					return os.WriteFile(path, append(append([]byte{}, comment...), old...), 0o600)
				}
			}
			if n, err := convertDevinHooksFile(path, dataDir, "devin", toEarlier, true, keep); err != nil || n != 3 {
				t.Fatalf("conversion = %d, %v; want 3 handlers", n, err)
			}
			restored, kept, err := RestoreManagedFileBackupsForRollback(
				dataDir, filepath.Join(root, "older-data"), root, map[string]bool{}, "",
			)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if edited {
				if len(restored) != 0 || len(kept) != 1 || !bytes.HasPrefix(got, comment) {
					t.Fatalf("the edit made during the conversion was not kept: restored=%v kept=%v file=%q", restored, kept, got)
				}
				return
			}
			if len(restored) != 1 || !bytes.Equal(got, pre) {
				t.Fatalf("untouched file: restored=%v kept=%v file=%q, want the pre-setup bytes %q", restored, kept, got, pre)
			}
		})
	}
}

// The save can also land after the writer's last journal note and just before
// the replacement, which is a replacement of the whole file. The writer must
// not replace a file that is not the one it read: the conversion starts again
// from the saved bytes and the save stays, in the file and out of the exact
// restore. An editor that saves under every attempt gets an error, not an
// overwritten file.
func TestDevinProjectRollbackConversionDoesNotReplaceAFileSavedBeforePublication(t *testing.T) {
	toEarlier := devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, false)
	comment := []byte("// operator note added during rollback\n")
	for _, saves := range []int{0, 1, devinConversionAttempts} {
		t.Run(fmt.Sprintf("%d saves before the replacement", saves), func(t *testing.T) {
			dataDir, root, path, pre := devinProjectSetUp(t)
			made := 0
			atomicFileBeforePublish = func(p string) {
				if made >= saves || !sameManagedTargetPath(p, path) {
					return
				}
				made++
				old, err := os.ReadFile(path)
				if err != nil {
					t.Error(err)
					return
				}
				if err := os.WriteFile(path, append(append([]byte{}, comment...), old...), 0o600); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { atomicFileBeforePublish = nil })
			n, err := convertDevinHooksFile(path, dataDir, "devin", toEarlier, true, nil)
			atomicFileBeforePublish = nil
			restored, kept, rerr := RestoreManagedFileBackupsForRollback(
				dataDir, filepath.Join(root, "older-data"), root, map[string]bool{}, "",
			)
			if rerr != nil {
				t.Fatal(rerr)
			}
			got, gerr := os.ReadFile(path)
			if gerr != nil {
				t.Fatal(gerr)
			}
			switch {
			case saves == 0:
				if err != nil || n != 3 || len(restored) != 1 || !bytes.Equal(got, pre) {
					t.Fatalf("untouched file: n=%d err=%v restored=%v file=%q, want the pre-setup bytes", n, err, restored, got)
				}
			case saves < devinConversionAttempts:
				if err != nil || n != 3 || len(restored) != 0 || len(kept) != 1 || !bytes.HasPrefix(got, comment) {
					t.Fatalf("save before publication: n=%d err=%v restored=%v kept=%v file=%q, want the save kept", n, err, restored, kept, got)
				}
			default:
				if !errors.Is(err, errManagedTargetMoved) || len(restored) != 0 || !bytes.HasPrefix(got, comment) {
					t.Fatalf("saves under every attempt: err=%v restored=%v file=%q, want a refusal that keeps the saves", err, restored, got)
				}
			}
		})
	}
}

// A held publication belongs to the record it was read from. When a later
// setup finds an edit and marks the record drifted before the rollback
// publishes, the publication changes nothing; on a record that did not move,
// it records the bytes the rollback committed.
func TestHeldExactRestoreOnlyChangesTheRecordItWasReadFrom(t *testing.T) {
	for _, moved := range []bool{false, true} {
		name := "record unchanged"
		if moved {
			name = "later setup marked the record drifted"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			path := filepath.Join(root, "config.json")
			pre := []byte(`{"operator":"pre"}`)
			setup := []byte(`{"operator":"pre","hook":"current"}`)
			converted := []byte(`{"operator":"pre","hook":"legacy"}`)
			edited := []byte(`{"operator":"changed","hook":"legacy"}`)
			if err := os.WriteFile(path, pre, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := captureManagedFileBackup(dataDir, "devin", "config", path); err != nil {
				t.Fatal(err)
			}
			if err := atomicWriteFile(path, setup, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := updateManagedFileBackupPostHash(dataDir, "devin", "config", path); err != nil {
				t.Fatal(err)
			}
			hold := holdManagedExactRestore(dataDir, "devin", path, setup)
			final := converted
			if moved {
				final = edited
				if err := os.WriteFile(path, edited, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := captureManagedFileBackup(dataDir, "devin", "config", path); err != nil {
					t.Fatal(err)
				}
			} else if err := atomicWriteFile(path, converted, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := hold(final); err != nil {
				t.Fatal(err)
			}
			restored, kept, err := RestoreManagedFileBackupsForRollback(
				dataDir, filepath.Join(root, "older-data"), root, map[string]bool{}, "",
			)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if moved {
				if len(restored) != 0 || len(kept) != 1 || !bytes.Equal(got, edited) {
					t.Fatalf("the publication re-armed a drifted record: restored=%v kept=%v file=%q", restored, kept, got)
				}
				return
			}
			if len(restored) != 1 || !bytes.Equal(got, pre) {
				t.Fatalf("restored=%v kept=%v file=%q, want the pre-setup bytes", restored, kept, got)
			}
		})
	}
}
