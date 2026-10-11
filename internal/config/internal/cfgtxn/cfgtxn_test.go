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

package cfgtxn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCommitRestoresGenerationAfterPostRenameFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	txn, err := Begin(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer txn.Close()
	first := []byte("config_version: 9\n")
	if _, err := txn.Commit(nil, first, false, 0o600, "first", "init"); err != nil {
		t.Fatal(err)
	}
	generationBefore, err := os.ReadFile(GenerationPath(path))
	if err != nil {
		t.Fatal(err)
	}

	failedSync := errors.New("directory fsync failed")
	txn.generationWrite = func(path string, data []byte, mode os.FileMode) error {
		if err := WriteFileDurable(path, data, mode); err != nil {
			return err
		}
		return failedSync
	}
	if _, err := txn.Commit(first, []byte("config_version: 9\n# rejected\n"), true, 0o600, "rejected", "edit"); !errors.Is(err, failedSync) {
		t.Fatalf("Commit error = %v, want directory fsync failure", err)
	}
	configAfter, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	generationAfter, err := os.ReadFile(GenerationPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configAfter, first) || !bytes.Equal(generationAfter, generationBefore) {
		t.Fatalf("failed Commit left config or generation record changed")
	}
}

func TestCommitDoesNotReplaceConfigWhenPreviousReadFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	txn, err := Begin(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer txn.Close()
	if _, _, _, err := txn.Read(); err != nil {
		t.Fatal(err)
	}

	// A non-cooperating process can change the path after Read. A symlink to
	// a directory makes the second read fail even when tests run as root.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(path), "unreadable")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Mkdir(GenerationPath(path), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := txn.Commit([]byte("original"), []byte("candidate"), true, 0o600, "test", "regression"); err == nil {
		t.Fatal("commit succeeded despite failed previous read")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("commit removed config path: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("commit replaced unreadable config path with %s", info.Mode())
	}
}

func TestCommitRejectsHandEditAfterCandidateRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("config_version: 9\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	txn, err := Begin(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer txn.Close()
	read, mode, exists, err := txn.Read()
	if err != nil {
		t.Fatal(err)
	}
	handEdit := []byte("config_version: 9\n# operator edit\n")
	if err := os.WriteFile(path, handEdit, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := txn.Commit(read, []byte("config_version: 9\n# candidate\n"), exists, mode, "cli:test", "edit"); !errors.Is(err, ErrConflict) {
		t.Fatalf("Commit error = %v, want conflict", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, handEdit) {
		t.Fatalf("hand edit changed: %q, %v", got, err)
	}
	if _, err := os.Stat(GenerationPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generation advanced after conflict: %v", err)
	}
}
