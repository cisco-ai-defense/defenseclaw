// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func claudeRollbackFixture(t *testing.T) (SetupOpts, string, []byte) {
	t.Helper()
	root := t.TempDir()
	opts := SetupOpts{DataDir: filepath.Join(root, "data"), HookExecutable: filepath.Join(root, "bin", "defenseclaw-hook.exe")}
	path := filepath.Join(root, "claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = path
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
	command, args := claudeCodeWindowsHookInvocation(opts, opts.HookExecutable)
	data, err := json.MarshalIndent(map[string]any{"foreign": map[string]any{"keep": "original formatting"},
		"hooks": map[string]any{"PreToolUse": []any{map[string]any{"matcher": "*", "hooks": []any{
			map[string]any{"type": "command", "command": command, "args": args},
			map[string]any{"type": "command", "command": "foreign-handler.exe"},
		}}}}}, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	data = append(append([]byte("\r\n"), data...), '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return opts, path, data
}

func readClaudeRollbackState(t *testing.T, path string) atomicTransformArtifactState {
	t.Helper()
	dir, err := bindAtomicTransformDirectory(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	state, err := atomicTransformBoundInspect(dir, filepath.Base(path), atomicTransformMaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func replaceClaudeRollbackFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	// Retain the old inode so NTFS cannot immediately reuse its file ID.
	if err := os.Rename(path, path+".foreign-predecessor"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:P(A;;GR;;;%s)(A;;FA;;;SY)(A;;FA;;;%s)", user.User.Sid, user.User.Sid, user.User.Sid))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeCodeRollbackRestoreExactOriginalAndRetry(t *testing.T) {
	opts, path, original := claudeRollbackFixture(t)
	c := NewClaudeCodeConnector()
	if count, err := c.ConvertHooksForRollback(opts); err != nil || count != 1 {
		t.Fatalf("convert = %d, %v", count, err)
	}
	if count, err := c.RestoreHooksAfterRollback(opts); err != nil || count != 1 {
		t.Fatalf("restore = %d, %v", count, err)
	}
	state := readClaudeRollbackState(t, path)
	if !bytes.Equal(state.data, original) {
		t.Fatal("inverse did not preserve exact original formatting and foreign entries")
	}
	if count, err := c.RestoreHooksAfterRollback(opts); err != nil || count != 0 {
		t.Fatalf("repeat restore = %d, %v", count, err)
	}
	if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(state, after) {
		t.Fatal("repeat restore changed original file identity or metadata")
	}
	for _, name := range []string{"config.yaml", "api-token", "hook-api-token", "active_connector.json", "picked_connector.json", "agent_selection.json"} {
		if _, err := os.Stat(filepath.Join(opts.DataDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inverse created lifecycle state %s: %v", name, err)
		}
	}
}

func TestClaudeCodeRollbackRestoreRefusesForeignState(t *testing.T) {
	for _, scenario := range []string{"changed", "same-converted", "same-original", "compare-retry", "commit-recheck"} {
		t.Run(scenario, func(t *testing.T) {
			opts, path, original := claudeRollbackFixture(t)
			c := NewClaudeCodeConnector()
			if _, err := c.ConvertHooksForRollback(opts); err != nil {
				t.Fatal(err)
			}
			converted := readClaudeRollbackState(t, path).data
			var foreign atomicTransformArtifactState
			if scenario == "compare-retry" || scenario == "commit-recheck" {
				hook := func(attempt int) {
					if attempt == 0 {
						replaceClaudeRollbackFixture(t, path, converted)
						foreign = readClaudeRollbackState(t, path)
					}
				}
				if scenario == "compare-retry" {
					t.Cleanup(setAtomicTransformBeforeCompareHookForTest(path, hook))
				} else {
					t.Cleanup(setAtomicTransformBeforeCommitHookForTest(path, hook))
				}
			} else {
				data := converted
				if scenario == "changed" {
					data = []byte(`{"foreign":"edited"}`)
				} else if scenario == "same-original" {
					data = original
				}
				replaceClaudeRollbackFixture(t, path, data)
				foreign = readClaudeRollbackState(t, path)
			}
			if count, err := c.RestoreHooksAfterRollback(opts); err == nil || count != 0 || !strings.Contains(err.Error(), "could not be verified") {
				t.Fatalf("foreign restore = %d, %v", count, err)
			}
			if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(foreign, after) {
				t.Fatal("refused foreign bytes, inode, protection or metadata changed")
			}
		})
	}
}

func TestClaudeCodeRollbackRestoreRecoversPendingPublication(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(map[bool]string{false: "recoverable", true: "persistent"}[persistent], func(t *testing.T) {
			opts, path, original := claudeRollbackFixture(t)
			c := NewClaudeCodeConnector()
			clear := setAtomicTransformPhaseHookForTest(path, func(phase atomicTransformPhase, _ atomicTransformPhaseState) error {
				if phase == atomicTransformPhaseCleanupStarted {
					return errors.New("injected cleanup failure")
				}
				return nil
			})
			t.Cleanup(clear)
			if _, err := c.ConvertHooksForRollback(opts); err == nil {
				t.Fatal("conversion did not report retained cleanup evidence")
			}
			published := readClaudeRollbackState(t, path)
			if bytes.Equal(published.data, original) {
				t.Fatal("fixture did not publish the direct form before cleanup failure")
			}
			if !persistent {
				clear()
			} else {
				// A phase hook marks a durable boundary only once. Hold the
				// retained receipt without sharing to model persistent I/O
				// failure across recovery attempts, rather than a second fault in
				// the inverse's own cleanup after it has safely published.
				entries, err := filepath.Glob(filepath.Join(opts.DataDir, ".defenseclaw-cas-v2-*"))
				if err != nil || len(entries) == 0 {
					t.Fatalf("no retained receipts to hold: %v", err)
				}
				for _, entry := range entries {
					name, err := windows.UTF16PtrFromString(entry)
					if err != nil {
						t.Fatal(err)
					}
					handle, err := windows.CreateFile(name, windows.GENERIC_READ,
						0, nil, windows.OPEN_EXISTING,
						windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = windows.CloseHandle(handle) })
				}
			}
			count, err := c.RestoreHooksAfterRollback(opts)
			if persistent {
				if err == nil || count != 0 || !strings.Contains(err.Error(), "retained recovery evidence") {
					t.Fatalf("persistent restore = %d, %v", count, err)
				}
				if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(published, after) {
					t.Fatal("persistent recovery failure altered settings")
				}
				entries, _ := filepath.Glob(filepath.Join(opts.DataDir, ".defenseclaw-cas-v2-*"))
				if len(entries) == 0 {
					t.Fatal("persistent failure discarded active CAS evidence")
				}
				return
			}
			if err != nil || count != 1 {
				t.Fatalf("recover and restore = %d, %v", count, err)
			}
			if after := readClaudeRollbackState(t, path); !bytes.Equal(after.data, original) {
				t.Fatal("recovery did not restore exact original")
			}
		})
	}
}

func TestClaudeCodeRollbackWitnessFailurePreventsPublication(t *testing.T) {
	opts, path, original := claudeRollbackFixture(t)
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	before := readClaudeRollbackState(t, path)
	previous := atomicFileBeforePrivatePublish
	atomicFileBeforePrivatePublish = func(destination string) error {
		if filepath.Base(destination) == claudeCodeRollbackWitnessName {
			return errors.New("injected witness publication failure")
		}
		return nil
	}
	t.Cleanup(func() { atomicFileBeforePrivatePublish = previous })
	if _, err := NewClaudeCodeConnector().ConvertHooksForRollback(opts); err == nil {
		t.Fatal("missing durable witness allowed conversion")
	}
	if after := readClaudeRollbackState(t, path); !bytes.Equal(after.data, original) {
		t.Fatal("witness failure published a weaker hook")
	}
	if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(before, after) {
		t.Fatal("unpublished conversion changed original identity or metadata")
	}
	// The backup alone is not identity authority. Even though its bytes equal
	// the unchanged guarded settings, missing publication proof must remain an
	// explicit refusal rather than claiming that hook protection was verified.
	if count, err := NewClaudeCodeConnector().RestoreHooksAfterRollback(opts); err == nil || count != 0 ||
		!strings.Contains(err.Error(), "could not be verified") {
		t.Fatalf("restore after witness-write failure = %d, %v; want fail-closed refusal", count, err)
	}
	if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(before, after) {
		t.Fatal("missing-witness refusal changed original guarded file")
	}
}

func TestClaudeCodeRollbackRestoreRecoversOwnInversePublication(t *testing.T) {
	opts, path, original := claudeRollbackFixture(t)
	c := NewClaudeCodeConnector()
	if _, err := c.ConvertHooksForRollback(opts); err != nil {
		t.Fatal(err)
	}
	clear := setAtomicTransformPhaseHookForTest(path, func(phase atomicTransformPhase, _ atomicTransformPhaseState) error {
		if phase == atomicTransformPhaseCleanupStarted {
			return errors.New("injected inverse cleanup failure")
		}
		return nil
	})
	t.Cleanup(clear)
	if _, err := c.RestoreHooksAfterRollback(opts); err == nil {
		t.Fatal("inverse cleanup failure was hidden")
	}
	before := readClaudeRollbackState(t, path)
	if !bytes.Equal(before.data, original) {
		t.Fatal("fixture did not publish the inverse before cleanup failure")
	}
	clear()
	if count, err := c.RestoreHooksAfterRollback(opts); err != nil || count != 0 {
		t.Fatalf("inverse recovery/noop = %d, %v", count, err)
	}
	if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(before, after) {
		t.Fatal("recovery replayed an already-published inverse")
	}
}

func TestClaudeCodeRollbackRestoreNoConversionNoop(t *testing.T) {
	opts, path, _ := claudeRollbackFixture(t)
	if err := os.WriteFile(path, []byte(`{"foreign":"only"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := readClaudeRollbackState(t, path)
	if count, err := NewClaudeCodeConnector().RestoreHooksAfterRollback(opts); err != nil || count != 0 {
		t.Fatalf("unconverted restore = %d, %v", count, err)
	}
	if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(before, after) {
		t.Fatal("no-conversion restore changed foreign settings")
	}
}

func TestClaudeCodeRollbackRestoreMissingAgentNoop(t *testing.T) {
	root := t.TempDir()
	opts := SetupOpts{DataDir: filepath.Join(root, "data")}
	path := filepath.Join(root, "unconfigured-agent", "settings.json")
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = path
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
	if count, err := NewClaudeCodeConnector().RestoreHooksAfterRollback(opts); err != nil || count != 0 {
		t.Fatalf("missing agent restore = %d, %v", count, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restore created an unconfigured agent profile: %v", err)
	}
}

func TestClaudeCodeRollbackRestoreRefusesChangedEvidence(t *testing.T) {
	for _, scenario := range []string{"backup-replaced", "witness-missing", "witness-malformed", "witness-oversize"} {
		t.Run(scenario, func(t *testing.T) {
			opts, path, _ := claudeRollbackFixture(t)
			c := NewClaudeCodeConnector()
			if _, err := c.ConvertHooksForRollback(opts); err != nil {
				t.Fatal(err)
			}
			backupPath := filepath.Join(opts.DataDir, "backups", claudeCodeRollbackBackupName)
			proofPath := filepath.Join(opts.DataDir, "backups", claudeCodeRollbackWitnessName)
			switch scenario {
			case "backup-replaced":
				data, err := os.ReadFile(backupPath)
				if err != nil {
					t.Fatal(err)
				}
				replaceClaudeRollbackFixture(t, backupPath, data)
			case "witness-missing":
				if err := os.Remove(proofPath); err != nil {
					t.Fatal(err)
				}
			case "witness-malformed", "witness-oversize":
				data := []byte(`{"version":1,"unknown":true}`)
				if scenario == "witness-oversize" {
					data = bytes.Repeat([]byte("x"), atomicTransformMaxIntentBytes+1)
				}
				if err := os.WriteFile(proofPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := readClaudeRollbackState(t, path)
			if _, err := c.RestoreHooksAfterRollback(opts); err == nil {
				t.Fatal("changed or missing evidence authorized inverse")
			}
			if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(before, after) {
				t.Fatal("evidence refusal changed settings bytes or metadata")
			}
		})
	}
}

func TestClaudeCodeRollbackRestoreRefusesEvidenceReplacementDuringCommit(t *testing.T) {
	for _, name := range []string{claudeCodeRollbackBackupName, claudeCodeRollbackWitnessName} {
		t.Run(name, func(t *testing.T) {
			opts, path, _ := claudeRollbackFixture(t)
			c := NewClaudeCodeConnector()
			if _, err := c.ConvertHooksForRollback(opts); err != nil {
				t.Fatal(err)
			}
			before := readClaudeRollbackState(t, path)
			// The proof itself is private durable authority, not self-authenticated
			// by its own inode. Once read for this inverse, however, neither it nor
			// its bound backup may change identity before publication.
			t.Cleanup(setAtomicTransformBeforeCommitHookForTest(path, func(attempt int) {
				if attempt == 0 {
					evidencePath := filepath.Join(opts.DataDir, "backups", name)
					data, err := os.ReadFile(evidencePath)
					if err != nil {
						t.Fatal(err)
					}
					replaceClaudeRollbackFixture(t, evidencePath, data)
				}
			}))
			if _, err := c.RestoreHooksAfterRollback(opts); err == nil {
				t.Fatal("same-content evidence replacement during commit authorized inverse")
			}
			if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(before, after) {
				t.Fatal("evidence replacement refusal changed current settings")
			}
		})
	}
}

func TestClaudeCodeRollbackRestoreRequiresBoundConversionHashes(t *testing.T) {
	for _, field := range []string{"old", "stage"} {
		t.Run(field, func(t *testing.T) {
			opts, path, _ := claudeRollbackFixture(t)
			c := NewClaudeCodeConnector()
			if _, err := c.ConvertHooksForRollback(opts); err != nil {
				t.Fatal(err)
			}
			witness, _, _, err := loadClaudeCodeRollbackWitness(path, opts)
			if err != nil {
				t.Fatal(err)
			}
			if field == "old" {
				witness.Conversion.Old.SHA256 = atomicTransformDigest([]byte("other original"))
			} else {
				witness.Conversion.Stage.SHA256 = atomicTransformDigest([]byte("other conversion"))
			}
			dir, err := openClaudeCodeRollbackEvidence(opts.DataDir, false)
			if err != nil {
				t.Fatal(err)
			}
			err = writeClaudeCodeRollbackWitness(dir, witness)
			_ = dir.Close()
			if err != nil {
				t.Fatal(err)
			}
			before := readClaudeRollbackState(t, path)
			if _, err := c.RestoreHooksAfterRollback(opts); err == nil {
				t.Fatal("unbound original/converted content witness authorized inverse")
			}
			if after := readClaudeRollbackState(t, path); !atomicTransformArtifactStatesEqualExact(before, after) {
				t.Fatal("hash-binding refusal changed settings")
			}
		})
	}
}

func TestClaudeCodeRollbackEvidenceCleanupPreservesForeignSourceReplacement(t *testing.T) {
	for _, outcome := range []string{"published", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			root := t.TempDir()
			if err := safefile.ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			dir, err := bindAtomicTransformDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			data, foreign := []byte("owned rollback evidence"), []byte("foreign replacement must survive")
			var sourcePath string
			var replaced atomicTransformArtifactState
			injected := errors.New("injected publication failure")
			err = writeClaudeCodeRollbackEvidenceWithPublisher(dir, claudeCodeRollbackWitnessName, data,
				func(source, destination string, info os.FileInfo, perm os.FileMode) error {
					sourcePath = source
					if outcome == "published" {
						if err := atomicFilePublish(source, destination, info, perm); err != nil {
							return err
						}
					} else if err := os.Rename(source, source+".retained-original"); err != nil {
						return err
					}
					// Reoccupy the source name at the real publisher-return seam,
					// before the writer's deferred cleanup. Capture full metadata so
					// a refused delete cannot silently modify the foreign inode.
					if err := os.WriteFile(source, foreign, 0o600); err != nil {
						return err
					}
					replaced = readClaudeRollbackState(t, source)
					if outcome == "failed" {
						return injected
					}
					return nil
				})
			if (outcome == "published" && err != nil) || (outcome == "failed" && !errors.Is(err, injected)) {
				t.Fatalf("evidence publication = %v", err)
			}
			if sourcePath == "" || !replaced.exists {
				t.Fatal("foreign source replacement seam was not exercised")
			}
			if after := readClaudeRollbackState(t, sourcePath); !atomicTransformArtifactStatesEqualExact(replaced, after) {
				t.Fatal("cleanup removed or changed foreign replacement at former stage name")
			}
			if outcome == "published" {
				if actual, err := os.ReadFile(filepath.Join(root, claudeCodeRollbackWitnessName)); err != nil || !bytes.Equal(actual, data) {
					t.Fatalf("owned evidence not published: %v", err)
				}
			}
		})
	}
}

func TestClaudeCodeRollbackEvidenceFailureCleansOnlyOwnedStage(t *testing.T) {
	root := t.TempDir()
	if err := safefile.ProtectDirectory(root); err != nil {
		t.Fatal(err)
	}
	dir, err := bindAtomicTransformDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	injected := errors.New("injected publication failure without replacement")
	var sourcePath string
	err = writeClaudeCodeRollbackEvidenceWithPublisher(dir, claudeCodeRollbackWitnessName, []byte("owned evidence"),
		func(source, _ string, _ os.FileInfo, _ os.FileMode) error {
			sourcePath = source
			return injected
		})
	if !errors.Is(err, injected) {
		t.Fatalf("publication error = %v", err)
	}
	if sourcePath == "" {
		t.Fatal("publication seam was not exercised")
	}
	if _, err := os.Stat(sourcePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed owned stage was not conditionally cleaned: %v", err)
	}
}
