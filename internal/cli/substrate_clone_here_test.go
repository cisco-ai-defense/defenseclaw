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
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// B2 2.3: --clone . (or a folder) means this checkout; anything else is a
// repository address and keeps today's checks.
func TestSubstrateCloneHereArg(t *testing.T) {
	dir := t.TempDir()
	for v, want := range map[string]bool{
		".": true, dir: true,
		"https://git.example.test/team/app.git": false,
		"git@git.example.test:team/app.git":     false,
		"no-such-folder-here":                   false,
	} {
		if got := substrateCloneHere(v); got != want {
			t.Errorf("substrateCloneHere(%q) = %t, want %t", v, got, want)
		}
	}
}

func TestSubstrateCloneHereRefusesRef(t *testing.T) {
	err := runSubstrateRun(&cobra.Command{}, &substrateRunFlags{clone: ".", ref: "main"}, []string{"claude"})
	if err == nil || !strings.Contains(err.Error(), "--clone . starts at this checkout's HEAD") {
		t.Fatalf("err = %v", err)
	}
}
