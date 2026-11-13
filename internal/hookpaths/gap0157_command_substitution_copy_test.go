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

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0157. A cp whose only source is a command substitution alone
// in double quotes has one source word and a fixed destination, as a quoted
// scalar parameter does: it is not a link operation that makes every earlier
// write of the command an unknown target.
func TestQuotedCommandSubstitutionIsOneCopySourceWord(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	want := []string{filepath.Join(cwd, "shot.png")}
	for _, command := range []string{
		`cp "$(cat shot.path)" shot.png`,
		`cp "$(echo a)" shot.png`,
	} {
		if got := QuotedDynamicCopyDestinations(command, cwd, home); !slices.Equal(got, want) {
			t.Errorf("%q: destinations = %q, want %q", command, got, want)
		}
	}
	// A substitution in a longer word, or unquoted (it may split into several
	// words), is not one source word.
	for _, command := range []string{
		`cp "x$(cat shot.path)" shot.png`,
		`cp $(cat shot.path) shot.png`,
		`cp "$(cat shot.path)" "$(cat other.path)" shot.png`,
	} {
		if got := QuotedDynamicCopyDestinations(command, cwd, home); len(got) != 0 {
			t.Errorf("%q: destinations = %q, want none", command, got)
		}
	}
}
