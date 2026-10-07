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
	if _, err := txn.Commit(first, 0o600, "first", "init"); err != nil {
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
	if _, err := txn.Commit([]byte("config_version: 9\n# rejected\n"), 0o600, "rejected", "edit"); !errors.Is(err, failedSync) {
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
