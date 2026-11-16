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

//go:build !windows

package cfgtxn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A generation update keeps the record's read access (the service group's
// 0640) and never keeps group or other write (p0 GAP-1153).
func TestRecordGenerationKeepsTheRecordMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	txn, err := Begin(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer txn.Close()
	raw := []byte("config_version: 9\n")
	if _, err := txn.Commit(nil, raw, false, 0o640, Writer{Actor: "first", Reason: "init"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ before, want os.FileMode }{{0o640, 0o640}, {0o600, 0o600}, {0o666, 0o644}} {
		if err := os.Chmod(GenerationPath(path), tc.before); err != nil {
			t.Fatal(err)
		}
		if _, err := txn.RecordGeneration(SHA256Hex(raw), Writer{Actor: "lifecycle", Reason: "ensure"}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(GenerationPath(path))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != tc.want {
			t.Fatalf("a %04o record is %04o after the update, want %04o", tc.before, got, tc.want)
		}
	}
}

// A temp file published read-only (the gateway's 0440 or a root-owned
// 0640) is still flushed: fsync needs no write access.
func TestSyncFileFlushesAReadOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte("{}"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := SyncFile(path); err != nil {
		t.Fatalf("flush of a read-only file: %v", err)
	}
	if err := SyncFile(filepath.Join(filepath.Dir(path), "missing.json")); err == nil {
		t.Fatal("a missing file flushed")
	}
}
