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

package sandboxapi

import (
	"slices"
	"testing"
)

func TestDisplayText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"src/lib/.git", "src/lib/.git"},
		{"✓ café → ok", "✓ café → ok"},
		{"a\tb\nc\rd", "a b c d"},
		{"x\x1b[2Jy", "x�[2Jy"},
		{"bell\x07", "bell�"},
		{"del\x7f", "del�"},
		{"c1\u009bz", "c1�z"},
		{"bidi\u202egnp.exe", "bidi\ufffdgnp.exe"},
		{"iso\u2066x\u2069", "iso\ufffdx\ufffd"},
		{"bad\xffutf8", "bad�utf8"},
	} {
		if got := DisplayText(tc.in); got != tc.want {
			t.Errorf("DisplayText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDisplayTexts(t *testing.T) {
	clean := []string{"a", "b"}
	if got := DisplayTexts(clean); &got[0] != &clean[0] {
		t.Fatal("a clean list was copied")
	}
	in := []string{"a", "b\x1b", "c"}
	got := DisplayTexts(in)
	if !slices.Equal(got, []string{"a", "b�", "c"}) || in[1] != "b\x1b" {
		t.Fatalf("DisplayTexts = %q (input %q)", got, in)
	}
	if DisplayTexts(nil) != nil {
		t.Fatal("nil in, non-nil out")
	}
}
