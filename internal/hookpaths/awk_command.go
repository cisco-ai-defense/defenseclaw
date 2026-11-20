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
// call, words[0] the awk program. The program text is the inline program, the
// -e sources, and with readFiles the text of a -f, --file, -E, --exec or
// -W exec program file as the hook client reads it (readActionScript: the
// file the system opens for the name, as the user). dynamic reports a command
// or a program file the call runs that is not fully known; the gateway
// answers it at the unknown tier (awkprog.DynamicReason). Nil for any other
// call and for an awk call with no command channel and no print redirect
// into a literal file (rel-1-0-10:GAP-1239), which is judged as before.
func awkCommandShell(words []string, cwd string, readFiles bool) (shell []string, dynamic bool) {
	if len(words) < 2 || !awkProgramName(words[0]) {
		return nil, false
	}
	call := awkprog.Call{Words: words}
	if readFiles {
		call.Files = func(name string) (string, bool) { return ReadProgramFile(name, cwd) }
	}
	reading := call.Read()
	if reading.Body == "" {
		return nil, reading.Dynamic
	}
	return []string{"sh", "-c", reading.Body}, reading.Dynamic
}
