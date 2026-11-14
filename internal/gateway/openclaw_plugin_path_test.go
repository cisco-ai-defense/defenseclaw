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
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	roots := []string{home}
	cases := map[string]bool{
		filepath.Join(home, "skills", "s1"): true,
		home:                                true,
		other:                               false,
		link:                                false,
		"relative/path":                     false,
		filepath.Join(home, "missing"):      false,
	}
	for p, want := range cases {
		if got := openClawPathUnderAny(p, roots); got != want {
			t.Errorf("openClawPathUnderAny(%q) = %v, want %v", p, got, want)
		}
	}
}
