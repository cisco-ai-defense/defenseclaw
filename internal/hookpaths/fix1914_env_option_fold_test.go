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

import "testing"

// FIX1914 sweep: env --chdir=DIR was matched in strings.ToLower(option) and
// DIR cut from the option at len("--chdir="). U+0130 lowers to ASCII i, so
// "--chd\u0130r=DIR" read as --chdir= with a DIR cut one byte late, and
// "-\u0130" as -i; env reads neither as those options. An option env does
// not know is a dynamic command, as for any other unknown option.
func TestFIX1914EnvWrapperOptionCaseChangingLetter(t *testing.T) {
	for _, option := range []string{"--chd\u0130r=C:/Users/u/x", "-\u0130", "--\u212aeep"} {
		if got := actionWindowsWrapperDecision("env", []string{"env", option, "ls"}, "C:/Users/u/w", "C:/Users/u", 0); got != "dynamic-command" {
			t.Errorf("env %s ls = %q, want dynamic-command (an unknown env option)", option, got)
		}
	}
	for _, option := range []string{"--chdir=C:/Users/u/x", "-i", "--CHDIR=C:/Users/u/x"} {
		if got := actionWindowsWrapperDecision("env", []string{"env", option, "ls"}, "C:/Users/u/w", "C:/Users/u", 0); got == "dynamic-command" {
			t.Errorf("env %s ls = %q, want the ASCII option read as before", option, got)
		}
	}
}
