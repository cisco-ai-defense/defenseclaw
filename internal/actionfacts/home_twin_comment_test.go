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

package actionfacts

import (
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// GAP-2473: only parser-reported comments are blanked, and offsets hold.
func TestWithoutShellCommentsBlanksOnlyComments(t *testing.T) {
	rows := []struct{ in, want string }{
		{"cp a $HOME/f # HOME", "cp a $HOME/f       "},
		{"a # HOME\nb # x", "a       \nb    "},
		{`echo "# HOME" a#HOME $# ${#HOME}`, `echo "# HOME" a#HOME $# ${#HOME}`},
		{"echo '# HOME'", "echo '# HOME'"},
		{"no hash", "no hash"},
		{"echo $(", "echo $("},
	}
	for _, row := range rows {
		for _, lang := range []syntax.LangVariant{syntax.LangPOSIX, syntax.LangBash} {
			got := withoutShellComments(row.in, lang)
			if got != row.want || len(got) != len(row.in) {
				t.Errorf("%v %q: got %q, want %q", lang, row.in, got, row.want)
			}
		}
	}
}

func TestHomeTwinsKeepTheirSpellingWithACommentThatNamesHome(t *testing.T) {
	const home = "/home/alice"
	if _, ok := homeResolvedSource("cp a $HOME/.defenseclaw/config.yaml # HOME", home); !ok {
		t.Fatal("homeResolvedSource declined a $HOME write with a # HOME comment")
	}
	if _, ok := homeResolvedSource("HOME=/tmp; cp a $HOME/.defenseclaw/config.yaml # note", home); ok {
		t.Fatal("homeResolvedSource kept the twin after a HOME assignment")
	}
	if _, ok := windowsProfileHomeTwin("cp a $USERPROFILE/.defenseclaw/config.yaml # USERPROFILE HOME"); !ok {
		t.Fatal("windowsProfileHomeTwin declined a $USERPROFILE write with a comment")
	}
	if _, ok := windowsProfileHomeTwin("USERPROFILE=/tmp; cp a $USERPROFILE/f # x"); ok {
		t.Fatal("windowsProfileHomeTwin kept the twin after a USERPROFILE assignment")
	}
}
