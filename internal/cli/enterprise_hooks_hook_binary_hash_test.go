// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The guardian's target and protected-copy hash routes retain the shared
// digest's opened-file checks, including refusal of a link at either path.
func TestGuardianHookHashRoutesRejectLinkedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	body := []byte("hook release")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	for name, hash := range map[string]func(string) (string, error){
		"target": guardianTargetHookSHA256Hex,
		"copy":   guardianCopyHookSHA256Hex,
	} {
		if got, err := hash(path); err != nil || got != want {
			t.Fatalf("%s hash %q, err %v; want %q", name, got, err, want)
		}
		linked := path + ".link"
		if err := os.Symlink(path, linked); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		if got, err := hash(linked); err == nil {
			t.Errorf("%s accepted a linked file with hash %q", name, got)
		}
		if err := os.Remove(linked); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGuardianTargetDigestVerdictAfterSharedRefusal(t *testing.T) {
	refusal := errors.New("changed during bounded digest")
	readFailure := errors.New("read denied")
	structureFailure := errors.New("attributes denied")
	for _, tc := range []struct {
		name          string
		plainSum      string
		plainErr      error
		structure     string
		structureErr  error
		wantDamage    string
		wantMissing   bool
		wantError     bool
		wantStructure int
	}{
		{name: "target vanished", plainErr: os.ErrNotExist, wantDamage: "missing", wantMissing: true},
		{name: "plain read failed", plainErr: readFailure, wantError: true},
		{name: "wrong hash", plainSum: "changed", wantDamage: "hash mismatch"},
		{name: "matching linked file", plainSum: "recorded", structure: "linked to another name (links=2)", wantDamage: "links=2", wantStructure: 1},
		{name: "matching healthy file", plainSum: "recorded", wantStructure: 1},
		{name: "attribute read failed", plainSum: "recorded", structureErr: structureFailure, wantError: true, wantStructure: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plainCalls, structureCalls := 0, 0
			verdict, err := decideGuardianTargetDigest("hook.exe", "recorded",
				func(string) (string, error) { return "", refusal },
				func(string) (string, error) {
					plainCalls++
					return tc.plainSum, tc.plainErr
				},
				func(string) (string, error) {
					structureCalls++
					return tc.structure, tc.structureErr
				},
			)
			if plainCalls != 1 || structureCalls != tc.wantStructure {
				t.Fatalf("plain calls %d, attribute calls %d; want 1 and %d", plainCalls, structureCalls, tc.wantStructure)
			}
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "hook.exe") || !errors.Is(err, refusal) {
					t.Fatalf("refused digest returned %q, err %v", verdict.damage, err)
				}
				if !errors.Is(err, readFailure) && !errors.Is(err, structureFailure) {
					t.Fatalf("fallback error was not wrapped: %v", err)
				}
				return
			}
			if err != nil || !strings.Contains(verdict.damage, tc.wantDamage) || verdict.missing != tc.wantMissing {
				t.Fatalf("decision %+v, err %v", verdict, err)
			}
			if verdict.refusal != refusal.Error() {
				t.Fatalf("refusal reason %q, want %q", verdict.refusal, refusal)
			}
			if tc.wantDamage != "" && !strings.Contains(verdict.damage, refusal.Error()) {
				t.Fatalf("damage omits the shared refusal: %q", verdict.damage)
			}
		})
	}
}

func TestGuardianTargetDigestHealthySharedHitDoesNotReadAgain(t *testing.T) {
	plainCalls, structureCalls := 0, 0
	verdict, err := decideGuardianTargetDigest("hook.exe", "recorded",
		func(string) (string, error) { return "recorded", nil },
		func(string) (string, error) { plainCalls++; return "", nil },
		func(string) (string, error) { structureCalls++; return "", nil },
	)
	if err != nil || verdict != (guardianTargetDigestDecision{}) || plainCalls != 0 || structureCalls != 0 {
		t.Fatalf("shared hit: decision %+v, err %v, plain reads %d, attribute reads %d", verdict, err, plainCalls, structureCalls)
	}
}
