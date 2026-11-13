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

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0135: the init step makes the volume root owner-only for the account.
func TestPrepareSubstrateDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	// Chown to oneself needs no privilege; as root, give it to 65532.
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 65532, 65532
	}
	if err := prepareSubstrateDataDir(dir, uid, gid, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, %v", info.Mode().Perm(), err)
	}
	for _, bad := range []string{"", "relative", "/", "/a/../b"} {
		if err := prepareSubstrateDataDir(bad, 1000, 1000, 0o700); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := prepareSubstrateDataDir(dir, 0, 0, 0o700); err == nil {
		t.Error("root as owner accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err == nil {
		if err := prepareSubstrateDataDir(link, uid, gid, 0o700); err == nil {
			t.Error("a symlink accepted")
		}
	}
}
