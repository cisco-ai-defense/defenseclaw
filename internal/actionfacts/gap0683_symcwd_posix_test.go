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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// POSIX shell words, a POSIX symbolic link and a POSIX rg working folder: on
// Windows the paths of t.TempDir() are not shell words (the backslashes are
// eaten), so this runs where the hook parses POSIX paths (GAP-0962).
// TestGAP0683RgSymbolicCwd: rg drops its physical working folder from a
// path before it matches an override glob, and walks a folder as the
// command names it. With the hook's working folder a symbolic link to the
// project, an absolute folder named through the link keeps the link in
// rg's paths, so an anchored glob matches nothing there (real rg 14.1.0
// run in the link reads deploy/id_ed25519 for the first row and nothing
// for the third).
func TestGAP0683RgSymbolicCwd(t *testing.T) {
	phys := g0683Folder(t)
	link := filepath.Join(t.TempDir(), "proj")
	if err := os.Symlink(phys, link); err != nil {
		t.Skipf("no symbolic link here: %v", err)
	}
	for _, row := range []struct {
		cmd  string
		read bool
	}{
		{"rg -g '!/deploy' KEY " + link, true},
		{"rg -g '!deploy/' KEY " + link, false},
		{"rg -g 'deploy/**' KEY " + link, false},
		{"rg -g 'deploy/**' KEY " + phys, true},
		{"rg -g '!/deploy' KEY " + phys, false},
	} {
		named := g0679Named(Analyze(Input{Tool: "exec", Command: row.cmd, CWD: link, ActiveHome: t.TempDir()}))
		got := slices.ContainsFunc(named, func(v string) bool { return strings.HasSuffix(filepath.ToSlash(v), "deploy/id_ed25519") })
		if got != row.read {
			t.Errorf("%s (cwd a link): deploy/id_ed25519 named = %v, real rg reads it = %v (named %v)", row.cmd, got, row.read, named)
		}
	}
}
