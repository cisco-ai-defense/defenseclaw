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

package winpath

import (
	"slices"
	"strings"
	"testing"
)

// GAP-1935: EnterpriseHookImagePathsIn found the image name in
// strings.ToLower(text) and cut text at those offsets. Growing letters
// (U+023A) in a vendor hook file before the command panicked the managed
// readers (guard, Copilot, Cursor, Codex requirements, Hermes); shrinking
// ones (U+212A, U+0130) cut the candidate path at the wrong byte. A file is
// now read as its ASCII twin.
func TestGAP1935HookImagePathsInCaseChangingLetters(t *testing.T) {
	launch := testBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	const twinLetters = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	for _, letter := range []string{"\u023a", "\u212a", "\u0130"} {
		letters := strings.Repeat(letter, len(twinLetters))
		for _, text := range []string{
			`{"note": "` + letters + `", "command": "` + launch + ` hook"}`,
			`& '` + launch + `' hook # ` + letters + ` & '` + launch + `' hook`,
		} {
			want := EnterpriseHookImagePathsIn(strings.Replace(text, letters, twinLetters, 1))
			if len(want) == 0 {
				t.Fatalf("the ASCII twin of %q names no image; the test lost its subject", text)
			}
			var got []string
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("EnterpriseHookImagePathsIn(%q) panicked: %v", text, recovered)
					}
				}()
				got = EnterpriseHookImagePathsIn(text)
			}()
			if !slices.Equal(got, want) {
				t.Errorf("EnterpriseHookImagePathsIn(%q) = %q, want %q as for the ASCII twin", text, got, want)
			}
		}
	}
}
