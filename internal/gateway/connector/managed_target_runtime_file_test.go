// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedTargetRuntimeFileAPIsReplaceAndRejectCollision(t *testing.T) {
	dir := t.TempDir()
	replacePath := filepath.Join(dir, "replace.runtime")
	if err := WriteManagedTargetRuntimeFile(replacePath, []byte("first")); err != nil {
		t.Fatalf("write managed target runtime file: %v", err)
	}
	if err := WriteManagedTargetRuntimeFile(replacePath, []byte("second")); err != nil {
		t.Fatalf("replace managed target runtime file: %v", err)
	}
	got, err := os.ReadFile(replacePath)
	if err != nil || string(got) != "second" {
		t.Fatalf("replacement bytes = %q, error = %v", got, err)
	}

	immutablePath := filepath.Join(dir, "immutable.runtime")
	if err := PublishManagedTargetRuntimeFileNoReplace(immutablePath, []byte("original")); err != nil {
		t.Fatalf("publish immutable managed target runtime file: %v", err)
	}
	err = PublishManagedTargetRuntimeFileNoReplace(immutablePath, []byte("replacement"))
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("no-replace collision error = %v, want os.ErrExist", err)
	}
	got, err = os.ReadFile(immutablePath)
	if err != nil || string(got) != "original" {
		t.Fatalf("immutable bytes after collision = %q, error = %v", got, err)
	}
}

func TestManagedTargetRuntimeFileRejectsOversizedPayload(t *testing.T) {
	data := make([]byte, atomicTransformMaxConfigBytes+1)
	err := WriteManagedTargetRuntimeFile(filepath.Join(t.TempDir(), "oversized.runtime"), data)
	if err == nil {
		t.Fatal("oversized managed target runtime payload was accepted")
	}
}
