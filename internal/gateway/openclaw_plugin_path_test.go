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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// In the separate-user layout the plugin credential may only scan paths of
// the OpenClaw account; a symlink out of an allowed root is refused.
func TestOpenClawPathUnderAny(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "oc-home")
	other := filepath.Join(root, "dc-data")
	for _, d := range []string{filepath.Join(home, "skills", "s1"), other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(home, "skills", "escape")
	// A Limited Windows token cannot make the symbolic link: that case skips
	// there and every other case runs (GAP-2158). The junction out of the
	// root is GAP-2182's own test.
	escape := testenv.TrySymlink(t, other, link)
	roots := []string{home}
	for _, tc := range []struct {
		name, path string
		want       bool
	}{
		{"skill folder", filepath.Join(home, "skills", "s1"), true},
		{"home", home, true},
		{"other folder", other, false},
		{"link out of the root", link, false},
		{"relative path", "relative/path", false},
		{"missing", filepath.Join(home, "missing"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.path == link {
				escape.Require(t)
			}
			if got := openClawPathUnderAny(tc.path, roots); got != tc.want {
				t.Errorf("openClawPathUnderAny(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
