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

//go:build linux || darwin

package cli

import (
	"strings"
	"testing"
)

// GAP-0249: every managed help path must describe the copy-only workspace,
// including flag descriptions inherited from the standalone command tree.
func TestSandboxManagedHelpIsCopyOnly(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
	}{
		{"", "ask your administrator"},
		{"run", "leave them in the sandbox for pull"},
		{"connect", "leave the changes in the sandbox for pull"},
		{"start", "copy"},
		{"review", "sandbox pull"},
		{"undo", "pull --apply"},
		{"doctor", "organization"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			args := []string{"sandbox"}
			if tc.command != "" {
				args = append(args, tc.command)
			}
			stdout, stderr, code := runLauncherRealTree(t, append(args, "--help")...)
			if code != 0 || !strings.Contains(stdout, tc.want) {
				t.Fatalf("help exit %d, stderr %q; want %q in %q", code, stderr, tc.want, stdout)
			}
			for _, stale := range []string{"mount", "--context", "--no-snapshot", "--new-snapshot", "sandbox setup"} {
				if strings.Contains(stdout, stale) {
					t.Errorf("managed help still mentions %q: %s", stale, stdout)
				}
			}
		})
	}
}
