//go:build !windows

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

package actionfacts

import (
	"slices"
	"testing"
)

// POSIX shell words, a POSIX symbolic link and a POSIX rg working folder: on
// Windows the paths of t.TempDir() are not shell words (the backslashes are
// eaten), so this runs where the hook parses POSIX paths (GAP-0962).
func TestGAP0684RgWorkingFolder(t *testing.T) {
	dir := g0684Folder(t)
	for _, row := range g0684Rows {
		cmd, hook := g0684Place(dir, row)
		got := g0683Rel(dir, g0679Named(Analyze(Input{Tool: "exec", Command: cmd, CWD: hook, ActiveHome: t.TempDir()})))
		for _, file := range row.want {
			if !slices.Contains(got, file) {
				t.Errorf("%s: real rg reads %s, the resolve names %v (weaker than rg)", row.cmd, file, got)
			}
		}
		exact := slices.Equal(got, row.want) || len(got) == 0 && len(row.want) == 0
		switch {
		case row.over == "" && !exact:
			t.Errorf("%s: the resolve names %v, real rg reads %v", row.cmd, got, row.want)
		case row.over != "" && exact:
			t.Errorf("%s: marked over (%s) but now exact: drop the mark", row.cmd, row.over)
		}
	}
}
