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

package enterprisehooks

import (
	"fmt"
	"strings"
	"testing"
)

func TestWindowsClaudeManagedHooksOnlyConflictReportsOnlyExplicitFalse(t *testing.T) {
	const path = `C:\Program Files\ClaudeCode\managed-settings.d\99-other.json`
	err := windowsClaudeManagedHooksOnlyConflict(path, map[string]interface{}{"allowManagedHooksOnly": false})
	if err == nil || !strings.Contains(err.Error(), path) ||
		!strings.Contains(err.Error(), "claude_code.allow_unmanaged_hooks") {
		t.Fatalf("explicit false conflict = %v, want the file and the opt-out key", err)
	}
	for name, settings := range map[string]map[string]interface{}{
		"absent":   {"model": "x"},
		"true":     {"allowManagedHooksOnly": true},
		"non-bool": {"allowManagedHooksOnly": "false"},
	} {
		if err := windowsClaudeManagedHooksOnlyConflict(path, settings); err != nil {
			t.Fatalf("%s: unexpected conflict %v", name, err)
		}
	}
}

func TestClaudeManagedHooksOnlyStateNames(t *testing.T) {
	if got := ClaudeManagedHooksOnlyState(false); got != ClaudeManagedHooksOnlyEnforced {
		t.Fatalf("default state = %q", got)
	}
	if got := ClaudeManagedHooksOnlyState(true); got != ClaudeManagedHooksOnlyDisabledByAdmin {
		t.Fatalf("opt-out state = %q", got)
	}
}

func TestCanonicalWindowsCursorApprovedForeignHooks(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	got, err := canonicalWindowsCursorApprovedForeignHooks([]string{" SHA256:" + strings.ToUpper(b), a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("canonical allowlist = %v", got)
	}
	if err := validateWindowsCursorApprovedForeignHooks(got); err != nil {
		t.Fatalf("canonical allowlist rejected: %v", err)
	}
	if err := validateWindowsCursorApprovedForeignHooks([]string{b, a}); err == nil {
		t.Fatal("unsorted published allowlist accepted")
	}
	if err := validateWindowsCursorApprovedForeignHooks([]string{}); err == nil {
		t.Fatal("empty-but-present published allowlist accepted")
	}
	if err := validateWindowsCursorApprovedForeignHooks(nil); err != nil {
		t.Fatalf("omitted allowlist rejected: %v", err)
	}
	if empty, err := canonicalWindowsCursorApprovedForeignHooks([]string{}); err != nil || empty != nil {
		t.Fatalf("empty config = (%v, %v), want omitted", empty, err)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), "md5:" + a} {
		if _, err := canonicalWindowsCursorApprovedForeignHooks([]string{bad}); err == nil {
			t.Fatalf("malformed digest %q accepted", bad)
		}
	}
	tooMany := make([]string, maxWindowsCursorApprovedForeignHooks+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("%064x", index)
	}
	if _, err := canonicalWindowsCursorApprovedForeignHooks(tooMany); err == nil {
		t.Fatal("oversized allowlist accepted")
	}
	equal, err := equalWindowsCursorApprovedForeignHooks([]string{a, b}, []string{b, "sha256:" + a})
	if err != nil || !equal {
		t.Fatalf("equivalent configured allowlist = (%v, %v)", equal, err)
	}
	equal, err = equalWindowsCursorApprovedForeignHooks(nil, []string{a})
	if err != nil || equal {
		t.Fatalf("stale published allowlist = (%v, %v), want mismatch", equal, err)
	}
	equal, err = equalWindowsCursorApprovedForeignHooks(nil, []string{})
	if err != nil || !equal {
		t.Fatalf("empty allowlists = (%v, %v), want equal", equal, err)
	}
}
