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

package reasons

import "testing"

// TestRV4F9CellCodesOnlyTheCommand: only the command is in code font, not
// the words after it, and "defenseclaw" in prose stays prose.
func TestRV4F9CellCodesOnlyTheCommand(t *testing.T) {
	for in, want := range map[string]string{
		"Remove it with: defenseclaw substrate secrets rm NAME, then add it again.":                        "Remove it with: `defenseclaw substrate secrets rm NAME`, then add it again.",
		"Add it again: defenseclaw substrate secrets rm NAME, then defenseclaw substrate secrets add NAME": "Add it again: `defenseclaw substrate secrets rm NAME`, then `defenseclaw substrate secrets add NAME`",
		"Use a host (see: defenseclaw substrate secrets templates), or ask.":                               "Use a host (see: `defenseclaw substrate secrets templates`), or ask.",
		"Store it with: defenseclaw substrate secrets set NAME.":                                           "Store it with: `defenseclaw substrate secrets set NAME`.",
		"It has no app.kubernetes.io/managed-by: defenseclaw label, and so on.":                            "It has no app.kubernetes.io/managed-by: defenseclaw label, and so on.",
		"Check it with: defenseclaw-gateway substrate doctor --cluster":                                    "Check it with: `defenseclaw-gateway substrate doctor --cluster`",
	} {
		if got := cell(in); got != want {
			t.Errorf("cell(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	for _, r := range Table {
		if got := cell(r.Fix); len(got) > 0 && got[len(got)-1] == '`' && r.Fix[len(r.Fix)-1] == '.' {
			t.Errorf("%s: the final period went into code font: %q", r.Code, got)
		}
	}
}
