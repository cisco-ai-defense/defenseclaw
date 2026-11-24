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
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

// GAP-0420: the record is of one actor: a later actor with the same name
// (another UID) is not resumed with it, and another computer has none.
func TestGAP0420TaskRecordIsOfOneActor(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	a := gap0420Actor("running")
	if _, ok := loadSubstrateTaskRecord(auth.StateDir(), a); ok {
		t.Fatal("a record on a computer that started nothing")
	}
	if err := saveSubstrateTaskRecord(auth.StateDir(), a, substrateTaskRecord{Prompt: "p"}); err != nil {
		t.Fatal(err)
	}
	// GAP-1085: Windows has no POSIX mode bits (Go reports 0666 for a
	// writable file); the record there takes the DACL of the per-user state
	// folder. Check the 0600 mode only where it exists.
	fi, err := os.Stat(substrateTaskRecordPath(auth.StateDir(), a))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("task record: %v %v", fi, err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("task record mode %v, want 0600", fi.Mode().Perm())
	}
	if _, ok := loadSubstrateTaskRecord(auth.StateDir(), a); !ok {
		t.Fatal("record not read back")
	}
	b := a
	b.UID = "uid-2"
	if _, ok := loadSubstrateTaskRecord(auth.StateDir(), b); ok {
		t.Fatal("a record of another actor with the same name was used")
	}
}
