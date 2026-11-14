// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"github.com/defenseclaw/defenseclaw/internal/awkprog"
)

// awkCommandShell is the sh -c call that stands for the commands an awk call
// starts through system(), print | and | getline when each is written as
// string literals (rel-1-0-10:GAP-0499): the readers of a nested shell body
// judge it as the hook running it directly. words are the static words of the
// call, words[0] the awk program. The program text is the inline program and
// the -e sources, and with readFiles the text of a -f program file the
// readers already open (inside the working directory). dynamic reports a
// command the call runs that is not fully known; the gateway answers it at the
// unknown tier (awkprog.DynamicReason). Nil for any other call and for an awk
// call with no command channel, which is judged as before.
func awkCommandShell(words []string, cwd string, readFiles bool) (shell []string, dynamic bool) {
	if len(words) < 2 || !awkProgramName(words[0]) {
		return nil, false
	}
	programs := awkprog.ArgvPrograms(words)
	if readFiles {
		for i := 1; i < len(words); i++ {
			option, value, attached := awkprog.OptionValue(words[i])
			if option != "f" {
				continue
			}
			if !attached {
				i++
				if i >= len(words) {
					break
				}
				value = words[i]
			}
			if !actionScriptInsideCWD(value, cwd) {
				continue
			}
			if code, read := readIndirectSource(value, cwd); read {
				programs = append(programs, code)
			}
		}
	}
	body, dynamic := awkprog.ProgramsShell(programs)
	if body == "" {
		return nil, dynamic
	}
	return []string{"sh", "-c", body}, dynamic
}
