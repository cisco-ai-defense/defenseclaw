// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

func atomicTransformEARegressionPayload(name, value string) []byte {
	payload := make([]byte, 8+len(name)+1+len(value))
	payload[5] = byte(len(name))
	binary.LittleEndian.PutUint16(payload[6:], uint16(len(value)))
	copy(payload[8:], name)
	copy(payload[9+len(name):], value)
	return payload
}

func atomicTransformEARegressionSet(t *testing.T, path string, payload []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var status windows.IO_STATUS_BLOCK
	result, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtSetEaFile").Call(
		file.Fd(), uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
	)
	if result != 0 {
		t.Fatalf("set ordinary EA on disposable fixture: NTSTATUS %#x", result)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicTransformV2PreservesOrdinaryEA(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "settings.json")
	if err := safefile.WritePrivate(path, []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	payload := atomicTransformEARegressionPayload("DEFENSECLAW_FIXTURE", "ordinary metadata")
	atomicTransformEARegressionSet(t, path, payload)
	err := atomicTransformFileWithStateDir(path, filepath.Join(root, "state"), 0o600,
		func(current []byte, exists bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte(`{"enabled":true,"updated":true}`)}, nil
		})
	if err != nil {
		t.Fatalf("replace benign settings while preserving ordinary EA: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	streams, err := atomicTransformV2WindowsBackupStreamsFromOpen(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range streams {
		if stream.ID == 2 && stream.Size == int64(len(payload)) && stream.SHA256 == atomicTransformDigest(payload) {
			return
		}
	}
	t.Fatal("ordinary EA was lost or changed by config replacement")
}

func TestAtomicTransformV2EACrashRecovery(t *testing.T) {
	for _, phase := range []atomicTransformPhase{
		atomicTransformPhaseAllocationPersisted,
		atomicTransformPhasePayloadMarkerBootstrap,
		atomicTransformPhaseStageMarkerBootstrap,
		atomicTransformPhaseReadyMarkerBootstrap,
		atomicTransformPhaseStagingLocated,
		atomicTransformPhaseIntentPersisted,
		atomicTransformPhasePublished,
	} {
		t.Run(string(phase), func(t *testing.T) {
			root := t.TempDir()
			path, stateDir := filepath.Join(root, "settings.json"), filepath.Join(root, "state")
			if err := safefile.WritePrivate(path, []byte("old")); err != nil {
				t.Fatal(err)
			}
			payload := atomicTransformEARegressionPayload("DEFENSECLAW_FIXTURE", "ordinary metadata")
			atomicTransformEARegressionSet(t, path, payload)
			crash := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
			crash.Env = atomicTransformV2HardExitEnv(
				"DEFENSECLAW_V2_HARD_EXIT_HELPER=1", "DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
				"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir, "DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
				"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(phase), "DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
			)
			output, err := crash.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != atomicTransformV2HardExitCode {
				t.Fatalf("fixture crash failed: %v\n%s", err, output)
			}
			if err := recoverAtomicTransformV2(path, stateDir); err != nil {
				t.Fatalf("recover EA fixture: %v", err)
			}
			if err := recoverAtomicTransformV2(path, stateDir); err != nil {
				t.Fatalf("repeat recovery: %v", err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			streams, readErr := atomicTransformV2WindowsBackupStreamsFromOpen(file)
			file.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			found := false
			for _, stream := range streams {
				if stream.ID == 2 && stream.SHA256 == atomicTransformDigest(payload) {
					found = true
				}
			}
			if !found {
				t.Fatal("EA lost across crash recovery")
			}
			if err := atomicTransformFileWithStateDir(path, stateDir, 0o600,
				func([]byte, bool) (atomicTransformResult, error) {
					return atomicTransformResult{Data: []byte("usable after recovery")}, nil
				}); err != nil {
				t.Fatalf("recovered config remains blocked: %v", err)
			}
		})
	}
}

func TestAtomicTransformV2AllocationRejectsForeignEA(t *testing.T) {
	root := t.TempDir()
	path, stateDir := filepath.Join(root, "settings.json"), filepath.Join(root, "state")
	if err := safefile.WritePrivate(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	atomicTransformEARegressionSet(t, path, atomicTransformEARegressionPayload("DEFENSECLAW_FIXTURE", "ordinary metadata"))
	crash := errors.New("stop fixture after staging EA")
	var retained string
	restore := setAtomicTransformPhaseHookForTest(path, func(phase atomicTransformPhase, state atomicTransformPhaseState) error {
		if phase != atomicTransformPhaseStageMarkerBootstrap {
			return nil
		}
		retained = state.StagedProvisional
		atomicTransformEARegressionSet(t, retained, atomicTransformEARegressionPayload("OPERATOR_FIXTURE", "retain this metadata"))
		return crash
	})
	err := atomicTransformFileWithStateDir(path, stateDir, 0o600,
		func([]byte, bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte("new")}, nil
		})
	restore()
	if !errors.Is(err, crash) {
		t.Fatalf("expected injected stop: %v", err)
	}
	if err := recoverAtomicTransformV2(path, stateDir); err == nil {
		t.Fatal("foreign EA-bearing stage was discarded")
	}
	if _, err := os.Stat(retained); err != nil {
		t.Fatal("foreign stage was not retained", err)
	}
	if content, err := os.ReadFile(path); err != nil || !bytes.Equal(content, []byte("old")) {
		t.Fatal("original config changed", err)
	}
}

func TestAtomicTransformV2EAReceiptCompatibility(t *testing.T) {
	receipt := atomicTransformV2Receipt{OldExists: true, Old: atomicTransformV2Artifact{PreservedMetadataSHA256: "legacy"}}
	state := atomicTransformArtifactState{preservedMetadataDigest: "legacy", canonicalEAMetadataDigest: "canonical"}
	if !atomicTransformV2PublishedMetadataMatches(receipt, state) {
		t.Fatal("legacy raw witness no longer matches")
	}
	state.preservedMetadataDigest = "different"
	if atomicTransformV2PublishedMetadataMatches(receipt, state) {
		t.Fatal("legacy raw witness accepted EA drift")
	}
	receipt.OldPreservedEAMetadataSHA256 = "canonical"
	if !atomicTransformV2PublishedMetadataMatches(receipt, state) {
		t.Fatal("explicit canonical witness did not match")
	}
	state.preservedMetadataDigest, state.canonicalEAMetadataDigest = "legacy", "different"
	if atomicTransformV2PublishedMetadataMatches(receipt, state) {
		t.Fatal("canonical mismatch fell back to legacy witness")
	}
	for _, test := range []atomicTransformV2Receipt{
		{Version: atomicTransformV2Version, OldPreservedEAMetadataSHA256: strings.Repeat("a", 64)},
		{Version: atomicTransformV2Version, OldExists: true, Remove: true, OldPreservedEAMetadataSHA256: strings.Repeat("a", 64)},
		{Version: atomicTransformV2Version, OldExists: true, OldPreservedEAMetadataSHA256: "invalid"},
	} {
		if err := validateAtomicTransformV2Receipt(test, "", "", "", ""); err == nil || !strings.Contains(err.Error(), "canonical EA") {
			t.Fatalf("invalid EA witness did not fail first: %v", err)
		}
	}
}

func TestAtomicTransformV2EAAllocationRetainsForeignLiveEdit(t *testing.T) {
	root := t.TempDir()
	path, stateDir := filepath.Join(root, "settings.json"), filepath.Join(root, "state")
	if err := safefile.WritePrivate(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	atomicTransformEARegressionSet(t, path, atomicTransformEARegressionPayload("FIXTURE", "ordinary metadata"))
	crash := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
	crash.Env = atomicTransformV2HardExitEnv(
		"DEFENSECLAW_V2_HARD_EXIT_HELPER=1", "DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
		"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir, "DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
		"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(atomicTransformPhaseAllocationPersisted), "DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
	)
	output, err := crash.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != atomicTransformV2HardExitCode {
		t.Fatalf("fixture crash: %v\n%s", err, output)
	}
	if err := os.WriteFile(path, []byte("operator edit"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverAtomicTransformV2(path, stateDir); err == nil {
		t.Fatal("foreign live edit was accepted as an owned allocation state")
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, []byte("operator edit")) {
		t.Fatal("operator edit was changed", err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), atomicTransformV2ReceiptPrefix) {
			return
		}
	}
	t.Fatal("allocation receipt was discarded despite a foreign live inode state")
}
