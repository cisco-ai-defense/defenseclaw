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

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --db names the real reason it cannot be exported (GAP-0008): another
// account's audit.db under a 0700 data directory said "is not an audit
// database file".
func TestCheckAuditExportDBNamesTheReason(t *testing.T) {
	root := t.TempDir()
	readable := filepath.Join(root, "audit.db")
	locked := filepath.Join(root, "locked")
	if err := os.WriteFile(readable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "audit.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(root, "unreadable.db")
	if err := os.WriteFile(unreadable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, path, want string
		needsDenied      bool
	}{
		{name: "readable file", path: readable},
		{name: "missing", path: filepath.Join(root, "missing.db"), want: "does not exist"},
		{name: "a folder", path: root, want: "is not an audit database file"},
		{name: "folder this account may not enter", path: filepath.Join(locked, "audit.db"), want: "permission denied", needsDenied: true},
		{name: "file this account may not read", path: unreadable, want: "permission denied", needsDenied: true},
	}
	denied := runtime.GOOS != "windows" && os.Geteuid() != 0
	if denied {
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unreadable, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needsDenied && !denied {
				t.Skip("needs a non-root Unix account to deny access")
			}
			err := checkAuditExportDB(tc.path)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("checkAuditExportDB = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("checkAuditExportDB = %v, want %q", err, tc.want)
			}
		})
	}
}
