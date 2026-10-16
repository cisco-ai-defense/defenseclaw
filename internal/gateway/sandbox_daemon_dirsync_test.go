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

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The sandbox daemon replaced its registrations file and then synced the
// directory on every OS, but Windows refuses to flush a directory handle
// ("Access is denied"), so every save of a registration failed there.
// writeDaemonFileAtomic replaces the file on every OS; only off Windows does
// it sync the directory (a missing directory is an error there and nothing
// is opened on Windows).
func TestWriteDaemonFileAtomicReplacesTheFileOnEveryOS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registrations.json")
	for _, want := range []string{"{\"v\":1}\n", "{\"v\":1,\"registrations\":[]}\n"} {
		if err := writeDaemonFileAtomic(path, []byte(want)); err != nil {
			t.Fatalf("writeDaemonFileAtomic: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("file = %q, want %q", got, want)
		}
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v (%v), want 0600", info, err)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("directory holds %v (%v), want only the registrations file", entries, err)
	}
	if err := syncDaemonDir(dir); err != nil {
		t.Fatalf("syncDaemonDir(%s): %v", dir, err)
	}
	err := syncDaemonDir(filepath.Join(dir, "missing"))
	if windows := runtime.GOOS == "windows"; (err == nil) != windows {
		t.Fatalf("syncDaemonDir of a missing directory on %s = %v", runtime.GOOS, err)
	}
}
