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

package watcher

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// Two mapping keys have one identity exactly when PyYAML builds one dict key
// from them (checked against PyYAML 6: 1, 1.0, True, 0b1 and 0x1 are one key;
// a quoted "1" and 1 are two).
func TestHermesYAMLKeyIdentityFollowsPyYAML(t *testing.T) {
	identity := func(text string) string {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte("? "+text+"\n: v\n"), &doc); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		return hermesYAMLKeyIdentity(doc.Content[0].Content[0])
	}
	same := [][]string{
		{"1", "1.0", "true", "True", "yes", "on", "0b1", "01", "0x1", "+1", "1_"},
		{"0", "false", "no", "off", "-0.0", "00", "0x0", "0.0"},
		{"~", "null", "Null", "NULL"},
		{`"1"`, `'1'`},
		{"main", `"main"`, `'main'`, "!!str main"},
		{"1.5", "1.50"},
		{"010", "8", "0b1000", "0x8"},
	}
	for _, group := range same {
		for _, text := range group[1:] {
			if got, want := identity(text), identity(group[0]); got != want {
				t.Errorf("%s = %q, %s = %q: PyYAML makes them one key", text, got, group[0], want)
			}
		}
	}
	distinct := [][2]string{
		{"1", `"1"`}, {"true", `"true"`}, {"~", `"null"`}, {"1", "1.5"}, {"010", "10"},
		{"main", "bin"}, {"2001-01-01", `"2001-01-01"`}, {"1:30", `"1:30"`}, {".inf", `".inf"`},
	}
	for _, pair := range distinct {
		if identity(pair[0]) == identity(pair[1]) {
			t.Errorf("%s and %s share an identity: PyYAML makes two keys", pair[0], pair[1])
		}
	}
}
