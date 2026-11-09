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
	"strings"
	"unicode"
	"unicode/utf8"
)

// OverLimitCommandBoundedTwin returns, for a limit-exceeded command (a shell
// call whose command text is over maxCommandBytes), the same call with the
// white space that pads each over-long text left out: none at its ends, and
// a run longer than maxKeptWhiteSpaceRun as one space (one line break where
// it holds a line break). The twin reads the same to the shell and to every
// rule, and is within the limits when the padding was all that put the call
// over them, so every rule judges it as it judges the unpadded command
// (GAP-0934). false when the call is not limit-exceeded, is a structured
// write tool (OverLimitWriteBoundedTwin owns those), has an over-long text
// that is not padded, or when the twin still exceeds a limit.
func OverLimitCommandBoundedTwin(input Input, facts Facts) (Input, bool) {
	if facts.Parse.Status != StatusLimitExceeded || StructuredWriteTool(input.Tool) {
		return Input{}, false
	}
	twin := input
	changed := false
	if len(input.Command) > maxCommandBytes {
		bounded, ok := boundedCommandText(input.Command)
		if !ok {
			return Input{}, false
		}
		twin.Command, changed = bounded, true
	}
	if len(strings.TrimSpace(string(input.Args))) != 0 {
		if len(input.Args) > maxOverLimitWriteArgsBytes || !utf8.Valid(input.Args) {
			return Input{}, false
		}
		reduction, ok := runOverLimitReducer(input.Args, &overLimitArgsReducer{commandTwin: true})
		if !ok {
			return Input{}, false
		}
		if reduction.boundedCommand {
			twin.Args, changed = reduction.args, true
		}
	}
	if !changed || len(twin.Args) > maxArgsJSONBytes || Analyze(twin).Parse.Status == StatusLimitExceeded {
		return Input{}, false
	}
	return twin, true
}

// boundedCommandText is a text over maxCommandBytes without the white space
// that pads it (see OverLimitCommandBoundedTwin); false when that form is
// still over the bound, or the text had no such padding.
func boundedCommandText(text string) (string, bool) {
	var out strings.Builder
	runStart := -1
	endRun := func(end int) {
		if run := text[runStart:end]; len(run) > maxKeptWhiteSpaceRun {
			if strings.Contains(run, "\n") {
				out.WriteByte('\n')
			} else {
				out.WriteByte(' ')
			}
		} else {
			out.WriteString(run)
		}
		runStart = -1
	}
	for index, char := range text {
		if unicode.IsSpace(char) {
			if runStart < 0 {
				runStart = index
			}
			continue
		}
		if runStart >= 0 {
			endRun(index)
		}
		out.WriteRune(char)
	}
	if runStart >= 0 {
		endRun(len(text))
	}
	bounded := strings.TrimSpace(out.String())
	return bounded, bounded != "" && len(bounded) <= maxCommandBytes && len(bounded) < len(text)
}
