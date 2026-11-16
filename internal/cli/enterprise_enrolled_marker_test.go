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
	"testing"
)

// GAP-1026, GAP-1034: the one marker of "the guardian enrolled this connector
// for the account before" is the connector's hook configuration in the
// account's DefenseClaw folder; a missing file, another connector's, a
// directory and empty inputs are never enrolled.
func TestEnterpriseConnectorEnrolledBefore(t *testing.T) {
	home := t.TempDir()
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".hookcfg.codex"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(hooks, ".hookcfg.cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		connector string
		want      bool
	}{{"codex", true}, {" Codex ", true}, {"claudecode", false}, {"cursor", false}, {"", false}} {
		if got := enterpriseHomeConnectorEnrolledBefore(home, tc.connector); got != tc.want {
			t.Errorf("connector %q: %t, want %t", tc.connector, got, tc.want)
		}
	}
	if enterpriseHomeConnectorEnrolledBefore("", "codex") || enterpriseConnectorEnrolledBefore(" ", "codex") {
		t.Error("an empty folder is enrolled")
	}
}

// enrollMarker writes the marker of connector in home for the status tests.
func enrollMarker(t *testing.T, home, connector string) {
	t.Helper()
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".hookcfg."+connector), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}
