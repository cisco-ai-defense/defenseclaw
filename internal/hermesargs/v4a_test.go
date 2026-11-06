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

package hermesargs

import (
	"reflect"
	"testing"
)

// TestV4ATargets pins the reading of a V4A patch as Hermes'
// parse_v4a_patch reads it.
func TestV4ATargets(t *testing.T) {
	w := func(path string) Target { return Target{Path: path, Write: true} }
	d := func(path string) Target { return Target{Path: path} }
	for _, test := range []struct {
		name, body string
		want       []Target
	}{
		{name: "update add delete", body: "*** Begin Patch\n*** Update File: a\n@@ f @@\n x\n+y\n*** Add File: /abs/b\n+z\n*** Delete File: ~/c\n*** End Patch\n",
			want: []Target{w("a"), w("/abs/b"), d("~/c")}},
		{name: "move", body: "*** Move File: a.md  ->  ~/.ssh/authorized_keys\n", want: []Target{d("a.md"), w("~/.ssh/authorized_keys")}},
		{name: "loose whitespace", body: "***Update \t File: ~/.ssh/authorized_keys \nctx line\n", want: []Target{w("~/.ssh/authorized_keys")}},
		{name: "crlf", body: "*** Begin Patch\r\n*** Update File: a\r\n+y\r\n*** End Patch\r\n", want: []Target{w("a")}},
		// Parsing starts after the last Begin line before the first End line.
		{name: "last begin", body: "*** Begin Patch\n*** Update File: a\n+y\n***  Begin  Patch\n*** Update File: b\n+y\n*** End Patch\n*** Update File: c\n+y\n",
			want: []Target{w("b")}},
		{name: "content lines are not headers", body: "*** Update File: a\n+*** Update File: b\n *** Delete File: c\n", want: []Target{w("a")}},
		{name: "update without hunk", body: "*** Update File: a\n@@ f @@\n*** Add File: b\n"},
		{name: "update only a no-newline marker", body: "*** Update File: a\n\\ No newline at end of file\n"},
		{name: "empty path", body: "*** Delete File:   \n"},
		{name: "move without destination", body: "*** Move File: a -> \n"},
		{name: "traversal", body: "*** Delete File: x/../../.ssh/authorized_keys\n"},
		{name: "no operations", body: "*** Begin Patch\n*** End Patch\n"},
		{name: "prose", body: "please update a\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsedTargets, parsed := V4ATargets(test.body)
			var got []Target
			for _, target := range parsedTargets {
				got = append(got, Target{Path: target.Path, Write: target.Write})
			}
			if parsed != (test.want != nil) || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %+v parsed=%t, want %+v", got, parsed, test.want)
			}
		})
	}
}

// TestV4ATargetsAddLines pins the text of an Add: its "+" lines as Hermes
// keeps them, up to the next operation header.
func TestV4ATargetsAddLines(t *testing.T) {
	got, parsed := V4ATargets("*** Begin Patch\n*** Add File: a\n+one\r\n+two\n*** Delete File: b\n+not a line of a\n*** End Patch\n")
	want := []Target{{Path: "a", Write: true, Add: true, Lines: []string{"one\r", "two"}}, {Path: "b"}}
	if !parsed || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v parsed=%t, want %+v", got, parsed, want)
	}
}
