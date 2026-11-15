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

package exactvalue

import (
	"encoding/base64"
	"slices"
	"testing"
)

func TestForms(t *testing.T) {
	if Forms("short") != nil {
		t.Fatal("a value under MinLen has forms")
	}
	v := `a"b\c/d+e=f?g h`
	got := Forms(v)
	for _, want := range []string{
		v,
		`a\"b\\c/d+e=f?g h`,
		base64.StdEncoding.EncodeToString([]byte(v)),
		base64.RawURLEncoding.EncodeToString([]byte(v)),
		"a%22b%5Cc%2Fd%2Be%3Df%3Fg+h",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("form %q missing from %q", want, got)
		}
	}
	seen := map[string]bool{}
	for _, f := range got {
		if seen[f] || f == "" {
			t.Errorf("repeated or empty form %q", f)
		}
		seen[f] = true
	}
	// A plain value: its JSON and URL forms are itself, listed once.
	plain := Forms("abcdefgh12345678")
	if plain[0] != "abcdefgh12345678" || slices.Index(plain[1:], "abcdefgh12345678") >= 0 {
		t.Errorf("plain value forms %q", plain)
	}
}
